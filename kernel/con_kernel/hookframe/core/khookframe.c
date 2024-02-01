#include "hook/khf_hook.h"
#include "lsm/khf_lsm.h"
#include "exec/exec_fake.h"
#include "khookframe.h"
#include "lsm/khf_commlsm.h"

int khf_init_sc_hook(u_int fh_if_supported);
int khf_init_sc_hook2(u_int fh_if_supported, int force_syscall_hook);
void khf_uninit_sc_hook(void);

/*
 *Note:
 *khf_init是默认不开启ftrace hook功能的
 *khf_init_with_ftrace默认是通过传入参数控制ftrace hook功能是否开启
 *
 *上面这样做目地是为了让hookframe框架在调用者使用时保持兼容
 *因为hookframe同时支持新旧不同版本的驱动
 */
int khf_init(const char* sysmaps[],
            size_t size)
{
    int rc = 0;

    rc = khf_hook_init(sysmaps,size);
    if(rc) { return rc; }
    
    rc = khf_init_sc_hook(0);
    if(rc < 0) {
        khf_hook_exit();
        goto out;
    }

    rc = khf_init_lsm_hook();
    if(rc) {
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }

    rc = khf_init_exec_fake();
    if(rc) {
        khf_uninit_lsm_hook();
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }

out:
    return rc;
}

int khf_init_with_ftrace(const char* sysmaps[],
            size_t size,u_int fh_if_supported)
{
    int rc = 0;

    rc = khf_hook_init(sysmaps,size);
    if(rc) { return rc; }
    
    rc = khf_init_sc_hook(fh_if_supported);
    if(rc < 0) {
        khf_hook_exit();
        goto out;
    }

    rc = khf_init_lsm_hook();
    if(rc) {
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }

    rc = khf_init_exec_fake();
    if(rc) {
        khf_uninit_lsm_hook();
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }

out:
    return rc;
}

void khf_uninit(void)
{
    khf_uninit_exec_fake();
    khf_uninit_lsm_hook();
    khf_uninit_sc_hook();
    khf_hook_exit();
}

int khf_init_ftrace_commlsm(const char* sysmaps[],
        size_t size,u_int fh_if_supported)
{
    int rc = 0;

    rc = khf_hook_init(sysmaps,size);
    if(rc) { return rc; }

    rc = khf_init_sc_hook(fh_if_supported);
    if(rc < 0) {
        khf_hook_exit();
        goto out;
    }

    rc = khf_init_commlsm_hook();
    if(rc) {
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }

    rc = khf_init_exec_fake();
    if(rc) {
        khf_uninit_commlsm_hook();
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }

out:
    return rc;
}

/* HOOK优先级:
 * 1. 优先使用lsm-hook: 依据系统决定是使用系统lsm还是kernel-lsm;
 * 2. 其次使用syscall-hook: syscall-hook未被占用, 或强制使用的情况;
 * 3. 最后使用ftrace-hook: syscall-hook被占用且未强制指定syscall-hook的情况;
 * */
int khf_init_ftrace_commlsm2(const char* sysmaps[],
        size_t size,u_int fh_if_supported, int force_syscall_hook)
{
    int rc = 0;

    rc = khf_hook_init(sysmaps,size);
    if(rc) { return rc; }

    rc = khf_init_sc_hook2(fh_if_supported, force_syscall_hook);
    if(rc < 0) {
        khf_hook_exit();
        goto out;
    }

    rc = khf_init_commlsm_hook();
    if(rc) {
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }
    //khf_enable_commlsm_hook();
    rc = khf_init_exec_fake();
    if(rc) {
        khf_uninit_commlsm_hook();
        khf_uninit_sc_hook();
        khf_hook_exit();
        goto out;
    }

out:
    return rc;
}

void khf_uninit_ftrace_commlsm(void)
{
    khf_uninit_exec_fake();
    khf_uninit_commlsm_hook();
    khf_uninit_sc_hook();
    khf_hook_exit();
}
