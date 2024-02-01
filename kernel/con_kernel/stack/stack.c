#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include "core/khf_core.h"
#include "sysfs/ktq_sysfs.h"
#include "utils/utils.h"
#include "utils/exe_cmdline.h"
#include "gnHead.h"

static u_int exec_snapshot = 0;

static void get_ptask_comm_pid(struct task_struct* task,
                        char comm[TASK_COMM_LEN],int* ppid)
{
    struct task_struct* parent = NULL;

    rcu_read_lock();
    parent = get_parent(task);
    if(parent) {
        *ppid = PID(parent); 
        ktq_get_task_comm(comm,
            TASK_COMM_LEN,task); 
    }
    rcu_read_unlock();
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
static int load_exec(struct linux_binprm *bprm)
#else
static int load_exec(struct linux_binprm *bprm, 
                        struct  pt_regs * regs)
#endif
{
    int err = 0;
    int ppid = -1;
    char* buf = NULL;
    int rc = -ENOEXEC;
    struct path path;
    char* cmdline = NULL;
    unsigned pathlen = 0;
    unsigned len = PAGE_SIZE;
    char pcomm[TASK_COMM_LEN] = {0};
    char* realpath = ERR_PTR(-ENOENT);

    if(!exec_snapshot) { return rc; }

    //属于内核线程或者kworker queue我们都不处理
    if(ktq_is_kthread(current)) {
        return rc;
    }

    buf = kzalloc(len,GFP_KERNEL);
    if(!buf) { return rc; }

    cmdline = ktq_get_exe_cmdline(bprm,
                            buf,&len);
    if(IS_ERR(cmdline)) { goto out; }

    err = khf_filp_path(bprm->file,&path);
    if(err) { goto out; }

    realpath = khf_get_pathname(&path,&pathlen);
    khf_path_put(&path);
    if(IS_ERR(realpath)) { goto out; }

    get_ptask_comm_pid(current,pcomm,&ppid);
    LOG_INFO("comm: %s,pid: %d,ppid: %d,pcomm: %s,exec: %s;cmdline: %s\n",
        CURRENT_COMM,CURRENT_PID,ppid,pcomm,realpath,cmdline);
    khf_put_pathname(realpath);

out:
    kfree(buf);

    return rc;
}

static struct linux_binfmt bin_exec = {
    .module         = THIS_MODULE,
    .load_binary    = load_exec,
};

static void stack_exec_init(void)
{
    khf_register_binfmt(&bin_exec);
}

static void stack_exec_exit(void)
{
    khf_unregister_binfmt(&bin_exec);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)) && \
    !defined(CONFIG_STACKTRACE)

static void (*show_stack_fun)(struct task_struct *tsk,unsigned long *stack);

static ssize_t ktq_stack_store(struct kobject* kobj, 
                        struct attribute *attr,
	      				const char * buf, size_t len)
{
    int pid = -1;
    struct task_struct* task = NULL;

	if(!buf || !len) {
		return -EINVAL;
	}

	if(len >= (sizeof("2147483647") - 1)) {
		return -E2BIG;
	}

    if(!show_stack_fun) { return -ENOSYS; }

    sscanf(buf,"%d",&pid);
    if(pid <= 1) { return -EINVAL; }

    task = khf_get_task_struct(pid);
    if(!task) { return -ESRCH; }

    show_stack_fun(task,NULL);
    khf_put_task_struct(task);
	
	return len;
}
#else 
static ssize_t ktq_stack_store(struct kobject* kobj, 
                        struct attribute *attr,
	      				const char * buf, size_t len)
{
    return -EINVAL;
}
#endif

static struct ktq_sysfs_entry pid_entry = 
	    __ATTR(pid,S_IWUSR,NULL,ktq_stack_store);


static ssize_t exec_snapshot_show(struct kobject* kobj,
                    struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
    ret = sprintf(buf,"%u",
        exec_snapshot);
    return ret;
}

static ssize_t exec_snapshot_store(struct kobject* kobj, 
                        struct attribute *attr,
	      				const char * buf, size_t len)
{
	char c;
    u_int bon = 0;

	if(!buf || !len) {
		return -EINVAL;
	}

	if(len > 1) {
		return -E2BIG;
	}

	c = buf[0];
	if(c != '0' && c != '1') {
		return -EINVAL;
	} 

	bon = (c == '0' ? 0 : 1);
    (void)xchg(&exec_snapshot,bon);

	return len;
}

static struct ktq_sysfs_entry exec_snapshot_entry = 
	    __ATTR(exec_snapshot,S_IRUGO | S_IWUSR,exec_snapshot_show,exec_snapshot_store);

static struct attribute* ktq_stack_def_attrs[] = {
	&pid_entry.attr,
    &exec_snapshot_entry.attr,
	NULL,
};
 
static void ktq_stack_obj_release(struct kobject *kobj)
{
	LOG_INFO("release %s kobject!\n",
                kobj->name);
	kfree(kobj);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)
ATTRIBUTE_GROUPS(ktq_stack_def);
#endif

struct kobj_type ktq_stack_sysfs_ktype = {
	.release = ktq_stack_obj_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)
    .default_groups = ktq_stack_def_groups,
#else
	.default_attrs = ktq_stack_def_attrs,
#endif
};

static struct kobject* ktq_stack_kobj = NULL;

int ktq_stack_init(void)
{
    int rc = 0;
    struct kobject* kobj = NULL;
    kobj = ktq_sysfs_sub_init_add("stack",
            &ktq_stack_sysfs_ktype);
    
    if(IS_ERR(kobj)) {
        rc = PTR_ERR(kobj);
        return rc;
    }

    ktq_stack_kobj = kobj;
    stack_exec_init();

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)) && \
    !defined(CONFIG_STACKTRACE)

    show_stack_fun = kallsyms_lookup_name("show_stack");
    if(!show_stack_fun) {
        LOG_ERROR("cant find show_stack\n");
    } else {
        LOG_INFO("find show_stack at: 0x%lx\n",
                (long)show_stack_fun);
    }
#endif

    LOG_INFO("init ktq_stack ok\n");
    return rc;
}

void ktq_stack_uninit(void)
{
    if(!ktq_stack_kobj) { return; }

    stack_exec_exit();
    ktq_sysfs_sub_del(ktq_stack_kobj);
    LOG_INFO("uninit ktq_stack\n");
}
