#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include "CKComm.h"

#if defined(TEST)
#define LOG_ERROR_SYS printf
#define LOG_ERROR_DEV printf
#define LOG_ERROR printf
#define LOG_DEBUG printf
#else
#include "log/log.h"
#endif

#include "epoll_func.h"

static int epoll_fd = -1;
sw_epoll_listen_info epoll_func_listen;



static int SW_epoll_Create(void)
{
    int efd = -1;

    efd = epoll_create(32);
	if (efd < 0)
	{
		LOG_ERROR_SYS("Epoll creat fail, error:%d, reason:%s", errno, strerror(errno));
    } else {
       CKComm::set_fd_cloexec(efd);
    }

	return efd;
}

static void SW_epoll_Destroy(int epoll_fd)
{
    if (0 > epoll_fd)
    {
        return;
    }

    close(epoll_fd);
    epoll_fd = -1;

    return;

}

static void SW_epoll_AddListen(int epoll_fd, sw_epoll_listen_info *epoll_listen)
{
	int ret = 0;
    struct epoll_event stEpEvt;

    if (NULL == epoll_listen)
    {
		LOG_ERROR_DEV("Epoll add listten fail, because invalue epoll_listen is NULL \n");
        return;
    }

    if (NULL == epoll_listen->epoll_callback)
    {
		LOG_ERROR_DEV("Epoll add listten fail, because epoll callback is NULL \n");
        return;
    }

    memset(&stEpEvt, 0 , sizeof(stEpEvt));
    stEpEvt.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    stEpEvt.data.ptr = (void *)epoll_listen;

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, epoll_listen->iListenFd, &stEpEvt);
	if (ret < 0)
	{
		LOG_ERROR_DEV("EpollCtl add %d path %s error:%s",
                epoll_listen->iListenFd, 
                epoll_listen->szPath, 
                strerror(errno));
	}
    return;
}

static bool SW_epoll_CheckWriteEvent(unsigned int uiEvents)
{
    if (uiEvents & EPOLLIN)
    {
        return true;
    }

    return false;
}

static int SW_epoll_ProcEvent(struct epoll_event *pstEpollEvent)
{
    bool bIsWriteEvent = true;
	sw_epoll_listen_info *epoll_listen = NULL;

    bIsWriteEvent = SW_epoll_CheckWriteEvent(pstEpollEvent->events);
    if (true != bIsWriteEvent)
    {
		LOG_ERROR_DEV("Epoll recv event not write event \n");
        return -1;
    }

    epoll_listen = (sw_epoll_listen_info *)pstEpollEvent->data.ptr;
    if (NULL == epoll_listen)
    {
    	LOG_ERROR_DEV("Epoll get epoll listen event fail,becaus get data ptr is NULL \n");
        return -1;
    }

    /*ulErrCode = to do ...*/
    epoll_listen->epoll_callback(epoll_listen->iListenFd,epoll_listen->ctx);

    return 0;
}


int SW_epoll_Wait(int epoll_fd)
{
    struct epoll_event astEpollEvent[1024];
    int ulErrCode = -1;
    int iReadyFdCount = 0;
    int i = 0;

    iReadyFdCount = epoll_wait(epoll_fd, astEpollEvent, 10, 1000);
    if (0 > iReadyFdCount)
    {
        if (errno != EINTR)
		{
            LOG_ERROR_DEV("Epoll wait error:%s", strerror(errno));
            return -1;
    	}
        return 0;
    }

    for (i = 0; i < iReadyFdCount; i++)
    {
        LOG_DEBUG("epoll wait read now\n");
        ulErrCode = SW_epoll_ProcEvent(&astEpollEvent[i]);
        if (0 != ulErrCode)
        {
            return ulErrCode;
        }
    }

    return 0;
}

static void SW_epoll_RemoveListen(int epoll_fd, sw_epoll_listen_info *epoll_listen)
{
	int ret = 0;
    struct epoll_event stEpEvt;

    if (NULL == epoll_listen)
    {
        return;
    }

    memset(&stEpEvt, 0 , sizeof(stEpEvt));

    stEpEvt.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    stEpEvt.data.ptr = (void *)epoll_listen;

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, epoll_listen->iListenFd, &stEpEvt);
	if (ret < 0)
	{
		LOG_ERROR_DEV("EpollCtl error:%d, reason:%s \n", errno, strerror(errno));
	}

    return;
}

static void epoll_listen_init(int sock,void* ctx,
            SW_EPOLL_CALLBACK_PF epoll_cb,
            SW_EPOLL_REINIT_FN reinit_cb)
{
	memset(&epoll_func_listen, 0, sizeof(epoll_func_listen));
    
    epoll_func_listen.ctx = ctx;
	epoll_func_listen.iListenFd = sock;
	epoll_func_listen.reinit_cb = reinit_cb;
	epoll_func_listen.epoll_callback = epoll_cb;
	strncpy(epoll_func_listen.szPath, "netlink", 
            sizeof(epoll_func_listen.szPath));

	return;
}

static void epoll_listen_reinit(int sock,void* ctx)
{
    epoll_func_listen.ctx = ctx;
    epoll_func_listen.iListenFd = sock;
}


static volatile int stop = 0;
static volatile int estop = 0;
int stop_poll_msg()
{
    int ret = estop;
    stop = 1;
    return ret;
}

void epoll_func_listen_run(void)
{
	int ret = -1;
    bool breinit = false;
    SW_EPOLL_REINIT_FN reinit_cb;
    sw_epoll_listen_info* pEpollLst = NULL;

    pEpollLst = &epoll_func_listen;
    reinit_cb = pEpollLst->reinit_cb;

	SW_epoll_AddListen(epoll_fd,pEpollLst);

	while(stop == 0)
	{
        if(breinit) {
            ret = reinit_cb(pEpollLst->iListenFd,
                        pEpollLst->ctx);
            if(ret) { 
                usleep(500000); //0.5 seconds
                continue;
            }

            breinit = false;
            SW_epoll_AddListen(epoll_fd,pEpollLst);
        }

		ret = SW_epoll_Wait(epoll_fd);
		if (0 != ret)
		{
			SW_epoll_RemoveListen(epoll_fd, &epoll_func_listen);
            LOG_ERROR_DEV("SW_epoll_Wait ret %d\n", ret);
			breinit = true;
		}
	}

    estop = 1;

	return;
}

int epoll_func_reinit(int sock,void* ctx)
{
    epoll_listen_reinit(sock,ctx);
    return 0;
}

int epoll_func_init(int sock,void* ctx,SW_EPOLL_CALLBACK_PF epoll_cb,
                    SW_EPOLL_REINIT_FN reinit_cb)
{
	epoll_fd = SW_epoll_Create();
	if (-1 == epoll_fd)
	{
		LOG_ERROR_DEV("Epoll func init fail \n");
		return -1;
	}

	epoll_listen_init(sock,ctx,epoll_cb,reinit_cb);

	return 0;
}

void epoll_func_destroy(void)
{
	SW_epoll_Destroy(epoll_fd);
}
