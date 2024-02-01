/*
 *CKTransferProxy.h: 2019-07-10 created by qudreams
 *transfer proxy for netlink and cdev
 */
#ifndef CK_TRANSFER_PROXY_H
#define CK_TRANSFER_PROXY_H

//transfer mode
enum {
    TM_NETLINK = 0, //netlink transfer protocol
    TM_CDEV, //cdev transfer protcol
};

//transfer protocol operations
//tp is a short name for transfer protocol
struct tp_ops_t {
    const char* name;//transfer protocol name
    int (*reinit)(int oldfd,void* data,void* ctx);
    ssize_t (*send)(int cmd,void* msg,size_t len);
    ssize_t (*read)(int rfd,void* buf,size_t buf_len);
    void (*release)(void);
};

typedef void (*KT_DATA_READY_FN)(void* data,size_t len,void* ctx);

class CKTransferProxy
{
public:
    CKTransferProxy(int mode,void* ctx,KT_DATA_READY_FN cb);
    ~CKTransferProxy();

    int Init(void* data);
    void Uninit();
    void Stop(); //stop epoll thread

    const char* GetName();
    ssize_t SendMsg2Kernel(int cmd,void* msg,size_t len);
    ssize_t ReadKMsg(int rfd,void* buf,size_t buf_len);
    void GotData(void* data,size_t data_len);
    int ReinitEpoll(int oldLstFd,void* ctx);
private:
    int m_mode; //transfer mode: TM_NETLINK,TM_CDEV
    void* m_initData; //初始化时传入的数据
    void* m_ctx;
    KT_DATA_READY_FN m_data_cb;
    tp_ops_t m_ops; //transfer protocol operations
};

#endif //end define