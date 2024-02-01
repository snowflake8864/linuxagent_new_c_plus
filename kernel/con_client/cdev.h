/*
 *cdev.h: 2019-07-10 created by qudreams
 *support character device transmition protocol
 */
#ifndef CDEV_H
#define CDEV_H

#include "epoll_func.h"

struct tp_ops_t;
int cdev_init(const char* cdev_name,void* ctx,
            SW_EPOLL_CALLBACK_PF epoll_cb,
            SW_EPOLL_REINIT_FN reinit_cb,
            tp_ops_t* ops);

#endif