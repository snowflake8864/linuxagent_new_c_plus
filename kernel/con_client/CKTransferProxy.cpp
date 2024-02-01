#include <errno.h>
#include <string.h>
#include "gnHead.h"
#include "CKTransferProxy.h"
#include "CKernelConnector.h"
#include "epoll_func.h"
#include "netlink_func.h"
#include "cdev.h"

CKTransferProxy::CKTransferProxy(int mode,void* ctx,KT_DATA_READY_FN cb)
                                :m_mode(mode)
                                ,m_ctx(ctx)
                                ,m_data_cb(cb)
{}

CKTransferProxy::~CKTransferProxy()
{ 
}

static int epoll_read_cb(int rfd,void* ctx)
{
    int nlen = 0;
    int nbuf = KTQ_DATA_MAX;
    CKTransferProxy* pthis = (CKTransferProxy*)ctx;

	char* buf = (char*)calloc(1,nbuf);
    if (!buf) {
        return KTQ_ENOMEM;
    }

	nlen = pthis->ReadKMsg(rfd,buf,nbuf);
	if (nlen < 0)
	{
		LOG_ERROR_DEV("recv msg, recv %s "
            "msg from kernel failed,because: %s",
            pthis->GetName(),strerror(errno));
        free(buf);
		return KTQ_EFAIL;
	}

    //此处内存不用free,外围负责free
    pthis->GotData(buf,nlen);

    return KTQ_OK;
}

static int epoll_reinit_cb(int oldLstFd,void* ctx)
{
    CKTransferProxy* pthis = (CKTransferProxy*)ctx;
    return pthis->ReinitEpoll(oldLstFd,ctx);
}

void CKTransferProxy::GotData(void* data,size_t data_len)
{
    m_data_cb(data,data_len,m_ctx);
}

int CKTransferProxy::ReinitEpoll(int oldLstFd,void* ctx)
{
    return m_ops.reinit(oldLstFd,m_initData,ctx);
}

ssize_t CKTransferProxy::ReadKMsg(int rfd,void* buf,size_t buf_len)
{
    return m_ops.read(rfd,buf,buf_len);
}

static void freeInitData(void* pinitdata,int mode)
{
    if(pinitdata) {
        ::free(pinitdata);
    }
}

int CKTransferProxy::Init(void* data)
{
    int rc = 0;
    void* pinitdata = NULL;

    if(m_mode == TM_NETLINK) {
        int proto = *(int*)data;
        pinitdata = calloc(1,sizeof(int));
        if(pinitdata == NULL) {
            return KTQ_ENOMEM;
        }
        memcpy(pinitdata,&proto,sizeof(proto));
        rc = netlink_init(proto,this,
                    epoll_read_cb,epoll_reinit_cb,&m_ops);
    } else if(m_mode == TM_CDEV) {
        std::string cdev_name = *(std::string*)data;
        pinitdata = calloc(1,cdev_name.size() + 1);
        if(pinitdata == NULL) {
            return KTQ_ENOMEM;
        }

        memcpy(pinitdata,cdev_name.c_str(),
                cdev_name.size());
        rc = cdev_init(cdev_name.c_str(),this,
                    epoll_read_cb,epoll_reinit_cb,&m_ops);
    } else {
        LOG_ERROR("unknown transfer mode: %d",m_mode);
        rc = KTQ_EINVAL;
    }

    if(rc) {
        freeInitData(pinitdata,m_mode);
        pinitdata = NULL;
    }

    m_initData = pinitdata;
    LOG_INFO("transfer proxy init,rc: %d\n",rc);
    return rc;
}

void CKTransferProxy::Uninit()
{
    m_ops.release();
    
    freeInitData(m_initData,m_mode);
    m_initData = NULL;
    LOG_INFO("uninit transfer proxy");
}

const char* CKTransferProxy::GetName()
{
    return m_ops.name;
}

extern int stop_poll_msg();
void CKTransferProxy::Stop()
{
     for (int i = 0; i < 5 ; i++) {
        if (stop_poll_msg()) {
            break;
        }
        sleep(1);
    }
}

ssize_t CKTransferProxy::SendMsg2Kernel(int cmd,void* msg,size_t len)
{
    return m_ops.send(cmd,msg,len);
}
