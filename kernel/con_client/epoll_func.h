#ifndef __EPOLL_FUNC_H__
#define __EPOLL_FUNC_H__

typedef int (*SW_EPOLL_CALLBACK_PF)(int iReadySocket,void* ctx);
typedef int (*SW_EPOLL_REINIT_FN)(int oldListenFd,void* ctx);

typedef struct epoll_listen_info
{
    void* ctx;
    int iListenFd;
    char szPath[256];
    SW_EPOLL_REINIT_FN reinit_cb; //用于重新初始化
    SW_EPOLL_CALLBACK_PF epoll_callback;
}sw_epoll_listen_info;

int epoll_func_init(int sock,void* ctx,
            SW_EPOLL_CALLBACK_PF epoll_cb,
            SW_EPOLL_REINIT_FN reinit_cb);
int epoll_func_reinit(int sock,void* ctx);
void epoll_func_destroy(void);
void epoll_func_listen_run(void);

#endif
