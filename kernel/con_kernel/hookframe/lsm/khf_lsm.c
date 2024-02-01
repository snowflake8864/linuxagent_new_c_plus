#include <linux/version.h>
#include "khf_lsm.h"
#include "khookframe.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#include "hook_lsm_empty.c"
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4,2,0)
#include "hook_lsm_ops.c"
#else
#include "hook_lsm_list.c"
#endif


int khf_init_lsm_hook(void)
{
    LOG_INFO("init khf lsm hook\n");
    do_lsm_hook_init();
    return 0;
}

void khf_uninit_lsm_hook(void)
{
    LOG_INFO("uninit khf lsm hook\n");
    do_lsm_hook_uninit();
}
