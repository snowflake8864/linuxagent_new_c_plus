#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/vfs.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "core/khf_core.h"
#include "khookframe.h"


#define SYS_OPEN_INDEX      KHF_SYSCALL_INDEX(__NR_open)
#define SYS_OPENAT_INDEX    KHF_SYSCALL_INDEX(__NR_openat)

#define SYS_CHMOD_INDEX     KHF_SYSCALL_INDEX(__NR_chmod)
#define SYS_FCHMOD_INDEX    KHF_SYSCALL_INDEX(__NR_fchmod)
#define SYS_FCHMODAT_INDEX  KHF_SYSCALL_INDEX(__NR_fchmodat)


KHF_HOOK_SYSCALL_DEFINE4(sys_openat, SYS_OPENAT_INDEX,
                int, dfd, const char __user *, pathname,
                int, flags, umode_t, mode);

////////////////////////////////////////////////////////////////////////////////
/*
    syscall : open
*/
//open操作不能出现费时太长的流程，否则会引起问题
KHF_HOOK_SYSCALL_DEFINE3(sys_open,SYS_OPEN_INDEX, 
                const char __user *,pathname,
                int, flags, umode_t, mode);
//
//////////////////////////////////////////////////////////////////////////////////////////////////////

KHF_HOOK_SYSCALL_DEFINE2(sys_chmod,SYS_CHMOD_INDEX,
        const char __user *, filename, umode_t, mode);

KHF_HOOK_SYSCALL_DEFINE2(sys_fchmod,SYS_FCHMOD_INDEX,
        unsigned int, fd, umode_t, mode);
KHF_HOOK_SYSCALL_DEFINE3(sys_fchmodat,SYS_FCHMODAT_INDEX,
        int, dfd, const char __user *, filename, umode_t, mode);


typedef struct open_ctx_s {
	mm_segment_t old_fs;	
	const char* pnewname;
}open_ctx_t;

static void hook_precall_openat(khf_regs_t* regs,khf_hook_ctx_t* ctx)
{
    unsigned lookup_flags = LOOKUP_FOLLOW;
    char* kpathname = NULL;

    KHF_REG_CAST_TO_ARGS(4,regs,int,dfd,
                const char __user*,pathname,
                int,flags,mode_t,mode);

    (void)mode;
    if(flags & O_NOFOLLOW) {
        lookup_flags = 0;
    }
    
    kpathname = khf_get_kernel_pathname(dfd,pathname,lookup_flags);
    if(KHF_IS_ERR_OR_NULL(kpathname)) { return; }
	if(strcmp(kpathname,"/home/qudreams/a.txt")) {
		goto out;
	}

	{
		open_ctx_t* open_ctx = NULL;
		char* pnewpath = vmalloc_user(PAGE_SIZE);
		if(!pnewpath) { goto out; }

		open_ctx = kzalloc(sizeof(*open_ctx),GFP_KERNEL);
		if(open_ctx) {
			regs->flag |= KHF_FLAG_STOP_NEXT;
			strcpy(pnewpath,"/home/qudreams/b.txt");
			regs->args[1] = (u_long)pnewpath;
			open_ctx->old_fs = get_fs();
			open_ctx->pnewname = pnewpath;
			ctx->data = open_ctx;
			set_fs(KERNEL_DS);
		} else {
			vfree(pnewpath);
		}
	}
out:
	khf_put_pathname(kpathname);
}

static void hook_postcall_openat(khf_regs_t* regs,khf_hook_ctx_t* ctx)
{
    if(ctx && !KHF_IS_ERR_OR_NULL(ctx->data)) {
		open_ctx_t* open_ctx = (open_ctx_t*)ctx->data;
		set_fs(open_ctx->old_fs);
        //LOG_INFO("postcall openat: %s\n",(char*)ctx->data);
		vfree(open_ctx->pnewname);
		kfree(open_ctx);
    }
}

static void hook_precall_open(khf_regs_t* regs,khf_hook_ctx_t* ctx)
{
    char* kpathname = NULL;
    unsigned lookup_flags = LOOKUP_FOLLOW;

    KHF_REG_CAST_TO_ARGS(3,regs,const char __user*,pathname,
                int,flags,mode_t,mode);

    (void)mode; //just to avoid warning
    if(flags & O_NOFOLLOW) {
        lookup_flags = 0;
    }
    
    kpathname = khf_get_kernel_pathname(AT_FDCWD,
                            pathname,lookup_flags);
    if(!KHF_IS_ERR_OR_NULL(kpathname)) {
        LOG_INFO("precall open: %s\n",kpathname);
        khf_put_pathname(kpathname);
    }
}

static void hook_postcall_open(khf_regs_t* regs,khf_hook_ctx_t* ctx)
{
    // LOG_INFO("postcall open\n");
}


static void hook_precall_chmod(khf_regs_t* regs,khf_hook_ctx_t* ctx)
{
    LOG_INFO("precall chmod\n");
}

static void hook_precall_fchmod(khf_regs_t* regs,khf_hook_ctx_t* ctx)
{
    LOG_INFO("precall fchmod\n");
}

static void hook_postcall_fchmodat(khf_regs_t* regs,khf_hook_ctx_t* ctx)
{
    LOG_INFO("postcall fchmodat\n");
}

static struct khf_hook_ops hook_opses[] = {
            KHF_INIT_HOOK_FIRST_OPS(hook_precall_openat,
                            hook_postcall_openat,
                            SYS_OPENAT_INDEX),
            KHF_INIT_HOOK_FIRST_OPS(hook_precall_open,
                            hook_postcall_open,
                            SYS_OPEN_INDEX),
            KHF_INIT_PREHOOK_FIRST_OPS(hook_precall_fchmod,
                            SYS_FCHMOD_INDEX),
            KHF_INIT_HOOK_OPS(NULL,
                        hook_postcall_fchmodat,
                        SYS_FCHMODAT_INDEX,
                        KHF_OPS_PRI_SECOND),
            KHF_INIT_HOOK_OPS(hook_precall_chmod,
                        NULL,
                        SYS_CHMOD_INDEX,
                        KHF_OPS_PRI_LAST),
        };


// syscall operations
int do_hook_syscalls(void)
{
    int rc = 0;

    //1.先注册系统调用hook
    rc = KHF_REGISTER_SC_HOOK(sys_openat,SYS_OPENAT_INDEX);
    if(rc) { goto out; }

  
    KHF_REGISTER_SC_HOOK(sys_open,SYS_OPEN_INDEX);
    KHF_REGISTER_SC_HOOK(sys_chmod,SYS_CHMOD_INDEX);
    KHF_REGISTER_SC_HOOK(sys_fchmod,SYS_FCHMOD_INDEX);
    KHF_REGISTER_SC_HOOK(sys_fchmodat,SYS_FCHMODAT_INDEX);

    //2.再注册针对每个系统调用hook的处操作
    khf_register_hook_ops(hook_opses,
            ARRAY_SIZE(hook_opses));
out:
    return rc;
}
