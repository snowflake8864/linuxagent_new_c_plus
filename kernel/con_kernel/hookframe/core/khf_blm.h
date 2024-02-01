#ifndef KHF_BLM_H
#define KHF_BLM_H

#include <linux/types.h>
#include "khf_core.h"
//简易布隆过滤器
//简易布隆过滤器
typedef struct {
    uint64_t hmin; //最小值
    uint64_t hmax; //最大值
}khf_blm_hval_t;

uint64_t khf_calc_blm_hval(const char* data,
                            size_t len);
bool khf_check_blm_hval(const char* data,size_t len,
                        const khf_blm_hval_t* blm_hval);
void khf_array_blm_hval(const char* arr[],size_t size,
                        khf_blm_hval_t* blm_hval);

#endif
