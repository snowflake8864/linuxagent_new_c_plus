#ifndef KHF_KALLSYMS_H
#define KHF_KALLSYMS_H

#include <linux/types.h>
int khf_load_kallsyms(const char* kallsyms,
		int (*cb)(const char* data,size_t len));

#endif
