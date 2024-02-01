#include <linux/types.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "core/khf_core.h"
#include "khookframe.h"


static unsigned long has_fake = 0;
static struct list_head fake_list;
static DEFINE_RWLOCK(fake_list_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
static int prepare_binprm(struct linux_binprm* bprm)
{
	loff_t pos = 0;
	
	memset(bprm->buf,0,BINPRM_BUF_SIZE);
	return kernel_read(bprm->file,bprm->buf,BINPRM_BUF_SIZE,&pos);
}
#endif

static int do_fake_exec(const char* fake,
                    struct linux_binprm* bprm)
{
    int rc = 0;
    struct file* file_kern = open_exec(fake);
    if(IS_ERR(file_kern)) {
        rc = PTR_ERR(file_kern);
        return rc;
    }

    {
        const char* old_fname = NULL;
        const char* old_interp = NULL;
        struct file* tmp_file = bprm->file;

        bprm->file = file_kern;
        old_interp = bprm->interp;
        old_fname = bprm->filename;
        bprm->filename = bprm->interp = fake;

        rc = prepare_binprm(bprm);
        if (rc < 0) {
            LOG_ERROR("prepare_binprm failed:%s, bprm->file:%p", 
                        current->comm,
                        bprm->file);
            allow_write_access(file_kern);
            fput(file_kern);
            bprm->file = tmp_file;
            bprm->filename = old_fname;
            bprm->interp = old_interp;
        } else {
            allow_write_access(tmp_file);
            fput(tmp_file);
        }
    }

    return rc;
}

static void need_fake_exe(const char* realpath,unsigned len,
                        struct linux_binprm *bprm)
{
    unsigned long flags;
    const char* fake = NULL;
    const char* p = realpath;
    const char* name = realpath;
    khf_exec_fake_t* elem = NULL;

    p = strrchr(realpath, '/');
    if (p) { name = p + 1; }

//    LOG_DEBUG("check need fake: realpath: %s,name: %s\n",\
                    realpath,name);
    
    read_lock_irqsave(&fake_list_lock,flags);
    list_for_each_entry(elem,&fake_list,lh) {
		int bfake = 0;
        const char *vfake = NULL;
        int (*fake_check)(const char *, const char *) = NULL;
        int (*fake_check2)(struct linux_binprm *, const char *, const char *) = NULL;
        if(elem->fake_check) {
            vfake = elem->fake;
            fake_check = elem->fake_check;
        } else if(elem->fake_check2) {
            vfake = elem->fake;
            fake_check2 = elem->fake_check2;
        }
        read_unlock_irqrestore(&fake_list_lock,flags);

        if (fake_check) {
            bfake = fake_check(realpath, name);
        } else if (fake_check2) {
            bfake = fake_check2(bprm, realpath, name);
        }
        if(bfake) { fake = vfake; goto out; }

        read_lock_irqsave(&fake_list_lock,flags);
	}
    read_unlock_irqrestore(&fake_list_lock,flags);

out:
    if(fake) { do_fake_exec(fake,bprm); }
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
static int _load_bin_check(struct linux_binprm *bprm)
#else
static int _load_bin_check(struct linux_binprm *bprm,
                            struct  pt_regs * regs)
#endif
{
    int ret = -ENOEXEC;
    unsigned int pathlen = 0;
    char* realname = ERR_PTR(-EBADF);
    
    //这里先判断是否有fake注册
    //如果没有就不用再进行下面的逻辑了
    //尤其是khf_file_pathname操作其实是比较慢的
    //我们在此处执行能快一点就快一点
    //这里不加锁了，可能会有点不准确，但我们是能够接受的
    if(!test_bit(0,&has_fake)) {
        return ret;
    }

    realname = khf_filp_pathname(bprm->file,&pathlen);
    if (IS_ERR(realname)) {
        return ret;
    }

    need_fake_exe(realname,pathlen,bprm);
    khf_put_pathname(realname);

    return ret;
}

static struct linux_binfmt fake_fmt = {
    .module         = THIS_MODULE,
    .load_binary    = _load_bin_check,
};

int khf_init_exec_fake(void)
{
    INIT_LIST_HEAD(&fake_list);
    return khf_register_binfmt(&fake_fmt);
}

void khf_uninit_exec_fake(void)
{
    khf_unregister_binfmt(&fake_fmt);
}

int khf_register_exec_fake(khf_exec_fake_t* exec_fake)
{
    int bexist = 0;
    int rc = -EAGAIN;
    unsigned long flags;
    khf_exec_fake_t* elem = NULL;

    BUG_ON((exec_fake == NULL) ||
          (exec_fake->fake == NULL) ||
          ((exec_fake->fake_check == NULL) &&
          (exec_fake->fake_check2 == NULL)));

    write_lock_irqsave(&fake_list_lock,flags);
	list_for_each_entry(elem,&fake_list,lh) {
		bexist = (!strcmp(elem->fake,
                    exec_fake->fake));
        if(bexist) { break; }
	}
    if(!bexist) {
        rc = 0;
        set_bit(0,&has_fake);
	    list_add_tail(&exec_fake->lh,&fake_list);
    }
    write_unlock_irqrestore(&fake_list_lock,flags);

    return rc;
}

void khf_unregister_exec_fake(khf_exec_fake_t* exec_fake)
{
    unsigned long flags;

    BUG_ON(exec_fake == NULL);
    //不支持在模块运行时进行unregister
    BUG_ON(THIS_MODULE->state == MODULE_STATE_LIVE);
    
    write_lock_irqsave(&fake_list_lock,flags);
    list_del(&exec_fake->lh);
    if(list_empty(&fake_list)) {
        clear_bit(0,&has_fake);
    }
    write_unlock_irqrestore(&fake_list_lock,flags);
}

