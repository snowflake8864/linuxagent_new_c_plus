#ifndef __NETLINK_FUNC_H__
#define __NETLINK_FUNC_H__

#include <linux/netlink.h>
#include "epoll_func.h"


#define NETLINK_PRO 20
typedef struct netlink_sock_info
{
	int sock;
	struct sockaddr_nl stSrcAddr;
    struct sockaddr_nl stDestAddr;
}nl_sock_info;

struct tp_ops_t;
int netlink_init(int protocol,void* ctx,
			SW_EPOLL_CALLBACK_PF cb,
			SW_EPOLL_REINIT_FN reinit_cb,
			tp_ops_t* ops);

#endif
