#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <sys/syscall.h>
#include "netlink_func.h"
#include "epoll_func.h"
#include "CKTransferProxy.h"

#if defined(TEST)
#define LOG_ERROR_SYS printf
#define LOG_ERROR_DEV printf
#define LOG_ERROR printf
#define LOG_INFO printf
#else
#include "log/log.h"
#endif

#define free_mm(x) { if (x) free(x), x = NULL; }

nl_sock_info *nl_sock = NULL;
static pthread_t th_listen;

static int SW_socket_ConfigNetlinkInfo(int sock, nl_sock_info *nl_sock)
{
	if (NULL == nl_sock)
	{
		LOG_ERROR_DEV("Netlink config netlink info fail, because the invalue netlink_sock_info is NULL\n");
		return -1;
	}

	nl_sock->sock = sock;
	nl_sock->stSrcAddr.nl_family = AF_NETLINK;
	nl_sock->stSrcAddr.nl_pid = getpid();
	nl_sock->stSrcAddr.nl_groups = 0;
	
	nl_sock->stDestAddr.nl_family = AF_NETLINK;
	nl_sock->stDestAddr.nl_pid = 0;
	nl_sock->stDestAddr.nl_groups = 0;
	
	return 0;
}

static void setCloExec(int sfd)
{
	int flags = 0;
	flags = fcntl(sfd,F_GETFD);
	if(flags < 0) { return; }

	flags |= FD_CLOEXEC;
	fcntl(sfd,F_SETFD,flags);
}

static nl_sock_info *SW_Creat_NetlinkSocket(int iProtocol)
{
	nl_sock_info *nl_sock = NULL;
	int sock = -1;
	int ret = -1;

	sock = socket(PF_NETLINK, SOCK_RAW, iProtocol);
    if (0 > sock)
    {
        LOG_ERROR_DEV("Netlink Socket Creat fail, erron: %d reason:%s\n", errno, strerror(errno));
        return NULL;
    }
	setCloExec(sock);

	nl_sock = (nl_sock_info *)malloc(sizeof(nl_sock_info));
	if (NULL == nl_sock)
	{
        LOG_ERROR_DEV("Netlink Socket Creat fail, because malloc nl_sock fail, out of memory size(%d), error: %d, reason: %s \n", sizeof(nl_sock_info), errno, strerror(errno));
		close(sock);
		return NULL;
	}

	memset(nl_sock, 0, sizeof(nl_sock_info));
	ret = SW_socket_ConfigNetlinkInfo(sock, nl_sock);
	if (-1 == ret)
	{
		if (NULL != nl_sock)
		{
			free(nl_sock);
		}
		close(sock);
		return NULL;
	}

	ret = bind(nl_sock->sock, (struct sockaddr *)&nl_sock->stSrcAddr, sizeof(nl_sock->stSrcAddr));
	if (-1 == ret)
	{
        LOG_ERROR_SYS("Netlink sock bind fail, error:%d, reason: %s\n", errno, strerror(errno));
		free(nl_sock);
		close(sock);
		
		return NULL;
	}

	return nl_sock;
}

static void SW_Destroy_NetlinkSocket(nl_sock_info *nl_sock)
{
	if (NULL == nl_sock)
	{
		return;
	}
	
	if (-1 != nl_sock->sock)
	{
		close(nl_sock->sock);
	}
	
	free(nl_sock);	

	return;
}

static struct nlmsghdr *SW_Creat_Nlmsg(size_t data_len, int msg_type, void *data)
{
	struct nlmsghdr *pstNetlinkMsg = NULL;

	if (NULL == data)
	{
		LOG_ERROR_DEV("Netlink Create Nlmsg fail, because invalue data will fill in netlink send to kernel is NULL \n");
		return NULL;
	}

	pstNetlinkMsg = (struct nlmsghdr *)malloc(NLMSG_SPACE(data_len));
	if (NULL == pstNetlinkMsg)
	{
    	LOG_ERROR_DEV("Netlink Create Nlmsg fail, because malloc NetlinkMsg struct fail,the errno is %d, reason:%s, out of memory size(%d) \n", errno, strerror(errno), NLMSG_SPACE(data_len));
		return NULL;	
	}

	memset(pstNetlinkMsg, 0, NLMSG_SPACE(data_len));
    pstNetlinkMsg->nlmsg_len = NLMSG_SPACE(data_len);
    pstNetlinkMsg->nlmsg_pid = getpid();
    pstNetlinkMsg->nlmsg_flags = 0;
    pstNetlinkMsg->nlmsg_type = msg_type;
    memcpy(NLMSG_DATA(pstNetlinkMsg), data, data_len);

	return pstNetlinkMsg;
}

static void SW_Config_IOVector(const struct nlmsghdr *pstNetlinkMsg, struct iovec *pstIOVector)
{
	if (!pstNetlinkMsg || !pstIOVector)
	{
        LOG_ERROR_DEV("Netlink Create Nlmsg fail, because invalue has NULL \n");
		return;
	}

	pstIOVector->iov_base = (void *)pstNetlinkMsg;
    pstIOVector->iov_len = pstNetlinkMsg->nlmsg_len;

	return;
}

static void SW_Config_SendMsg(nl_sock_info *nl_sock, struct iovec *pstIOVector, struct msghdr *pstSendMsg)
{
	if (!nl_sock || !pstIOVector || !pstSendMsg)
	{
        LOG_ERROR_DEV("Netlink send nl msg to kernel fail, because invalue has NULL \n");
		return;
	}

	pstSendMsg->msg_name = (void *)&nl_sock->stDestAddr;
    pstSendMsg->msg_namelen = sizeof(nl_sock->stDestAddr);
    pstSendMsg->msg_iov = pstIOVector;
    pstSendMsg->msg_iovlen = 1;

	return;
}

static ssize_t SW_Send_NlMsg(int msg_type, void *data, size_t data_len)
{
	struct nlmsghdr *pstNetlinkMsg = NULL;
    struct iovec stIOVector;
    struct msghdr stSendMsg;
    ssize_t iSendLen = 0;

    if (NULL == nl_sock || NULL == data)
    {
        LOG_ERROR_DEV("Netlink create netlink msg fail, because invalue has NULL \n");
		return -1;
    }

	pstNetlinkMsg = SW_Creat_Nlmsg(data_len, msg_type, data);
	if (NULL == pstNetlinkMsg)
	{	
        LOG_ERROR_DEV("Netlink create netlink msg fail \n");
		return -1;
	}

	memset(&stIOVector, 0, sizeof(stIOVector));
	memset(&stSendMsg, 0, sizeof(stSendMsg));

	SW_Config_IOVector(pstNetlinkMsg, &stIOVector);
	SW_Config_SendMsg(nl_sock, &stIOVector, &stSendMsg);

	iSendLen = sendmsg(nl_sock->sock, &stSendMsg, 0);
	if (0 > iSendLen)
	{
        LOG_ERROR_DEV("Netlink send msg to kernel fail,reason:%s, errno: %d \n",
			 strerror(iSendLen), iSendLen);
	}
	
	free_mm(pstNetlinkMsg);
	
	return iSendLen;
}

static pid_t mygettid() 
{
#ifdef _GNU_SOURCE
    return syscall(SYS_gettid);
#else
    return gettid();
#endif
}

static void *netlink_listen_thread(void *arg)
{
	long tid = (long)mygettid();

	LOG_INFO("netlink listen thread %ld start\n",tid);
	epoll_func_listen_run();
	LOG_INFO("netlink listen thread %ld exit\n",tid);

	return NULL;
}

static int netlink_create_recv_thread()
{
	int rc = 0;

	memset(&th_listen,0,sizeof(th_listen));
    rc = pthread_create(&th_listen, NULL, netlink_listen_thread, NULL);

	if (0 > rc)
	{
		LOG_ERROR_SYS("Netlink create recv thread fail,because: %s\n",
				strerror(rc));
		return -1;
	}
	
	return 0;
}

static void netlink_destroy(void)
{
	pthread_t null_th;

    if (nl_sock) {
        SW_Destroy_NetlinkSocket(nl_sock);
        nl_sock = NULL;
    }

	memset(&null_th,0,sizeof(null_th));
	if(!pthread_equal(null_th,th_listen)) {
		pthread_join(th_listen,NULL);
		memset(&th_listen,0,sizeof(th_listen));
	}

	LOG_INFO("netlink destroy");
}

static ssize_t netlink_read(int rfd,void* buf,size_t buf_len)
{
	ssize_t nrecv = 0;
	struct nlmsghdr *nlh = NULL;
	
	nrecv = recv(rfd,buf,buf_len,0);
	if(nrecv <= 0) { return nrecv; }

	nlh = (struct nlmsghdr *)buf;
	void* pdata = NLMSG_DATA(nlh);

	ssize_t data_len = nrecv - NLMSG_HDRLEN;
	memmove(buf,pdata,data_len);
	memset((char*)buf + data_len,0,nrecv - data_len);

	return data_len;
}

static int netlink_reinit(int oldLstFd,void* data,void* ctx)
{
	int rc = -1;
	if(!data || !ctx) {
		return rc;
	}

	(void)oldLstFd;

	if (nl_sock) {
        SW_Destroy_NetlinkSocket(nl_sock);
        nl_sock = NULL;
    }

	int nproto = *(int*)data;
	nl_sock = SW_Creat_NetlinkSocket(nproto);
    if (NULL == nl_sock)
    {
        LOG_ERROR_DEV("reinit netlink fail,"
			"because netlink socket creat fail\n");
        return rc;
    }

	rc = epoll_func_reinit(nl_sock->sock,ctx);
	if(rc) {
		LOG_ERROR_DEV("reinit netlink failed,"
			"because epoll_func_init failed\n");
		SW_Destroy_NetlinkSocket(nl_sock);
		nl_sock = NULL;
	}

	LOG_INFO("netlink_reinit ok\n");

	return rc;
}

#define netlink_send SW_Send_NlMsg

static void netlink_set_ops(tp_ops_t* ops)
{
	ops->name = "netlink";
	ops->read = netlink_read;
	ops->send = netlink_send;
	ops->reinit = netlink_reinit;
	ops->release = netlink_destroy;
}

int netlink_init(int nProtocol,void* ctx,SW_EPOLL_CALLBACK_PF cb,
					SW_EPOLL_REINIT_FN reinit_cb,tp_ops_t* ops)
{
    int ret = 0;

	if (nl_sock != NULL) {
    	LOG_ERROR_DEV("Netlink init fail, because netlink socket has been init \n");
        return -1;
	}

	nl_sock = SW_Creat_NetlinkSocket(nProtocol);
    if (NULL == nl_sock)
    {
        LOG_ERROR_DEV("Netlink init fail, because netlink socket creat fail\n");
        return -1;
    }
	
	netlink_set_ops(ops);

	ret = epoll_func_init(nl_sock->sock,ctx,cb,reinit_cb);
    if (-1 == ret)
    {
        netlink_destroy();
        return -1;
    }

	ret = netlink_create_recv_thread();
	if (-1 == ret)
	{
       	epoll_func_destroy();
		netlink_destroy();
        return -1;
	}

	LOG_INFO("netlink initial ok");
	return 0;
}
