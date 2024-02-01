#ifndef HOOK_H_
#define HOOK_H_

#include <asm/atomic.h>

/*
 *全局lsm-hook启用标识
 *无论是kylin-lsm,还是qaxkws-lsm，亦或是原生lsm
 *我们都会将该标识置位,当该标识开启时不会再启用syscall-hook
 *上述做的目地主要是为了应对某些特殊情况下的逻辑:
 *比如在一些场景下使用lsm-hook与fanotify即可满足要求，
 *并且避免了与其他厂商syscall-hook冲突
 */
extern int _hook_lsm_on; 

int ktq_hook_init(void);
void ktq_hook_exit(void);
void reset_old_syscall_hook(void);

#endif

