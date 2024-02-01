#ifndef __KHF_HOOK_H_
#define __KHF_HOOK_H_

#include <linux/types.h>

int khf_hook_init(const char* sysmaps[],
                size_t size);
void khf_hook_exit(void);
volatile void** khf_find_syscall_table(void);

#endif

