/*
 *proto.c: 2020-06-04 created by qudreams
 *support TLV protocol for tianqing kernel module
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "core/khf_core.h"
#include "gnHead.h"
#include "gnkernel.h"

static tlv_proto_fn_t tlv_cbs[TQ_PT_MAX] = {NULL};

int register_tlv_proto_callback(ktq_tlv_proto_cb_t* pcb)
{
    int rc = -EINVAL;

    //只能在模块初始化时进行注册
    BUG_ON(THIS_MODULE->state != MODULE_STATE_COMING);

    if(!pcb) { goto out; }

    if((pcb->pt <= TQ_PT_NONE) || 
        (pcb->pt >= TQ_PT_MAX))
    {
        goto out;
    }

    if(tlv_cbs[pcb->pt]) {
        rc = -EAGAIN;
        goto out;
    }

    rc = 0;
    tlv_cbs[pcb->pt] = pcb->pfunc;

out:
    return rc;
}

int unregister_tlv_proto_callback(ktq_tlv_proto_cb_t* pcb)
{
    int rc = -EINVAL;

    //不支持在模块运行时进行unregister
    BUG_ON(THIS_MODULE->state == MODULE_STATE_LIVE);

    if(!pcb) { goto out; }

    if((pcb->pt <= TQ_PT_NONE) || 
        (pcb->pt >= TQ_PT_MAX))
    {
        goto out;
    }

    if(tlv_cbs[pcb->pt] == NULL) {
        goto out;
    }

    rc = 0;
    tlv_cbs[pcb->pt] = NULL;

out:
    return rc;
}


