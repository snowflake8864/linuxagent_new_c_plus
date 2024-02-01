#ifndef CERNEL_CONNECTOR_H
#define CERNEL_CONNECTOR_H

#include <string>
#include <vector>
//#include <netlink/netlink.h>
//#include <netlink/msg.h>
#include "IKernelConnector.h"
#include "qh_thread/multi_thread.h"
#include "qh_thread/thread.h"
#include "thread_safe_queue.h"
#include "singleton.hpp"
#include "log/log.h"

const int kDispatchThreadNum = 4;


class CKCmdHandlers;
class CKTransferProxy;
// Multithread的4个线程从netlink收数据并放入缓存队列(这个可以后期考虑改为EasyThread线程组)
// Easytyhread线程组的线程负责进行任务派发
// 这样设计的原因是netlink的队列缓存很小，需要尽快收集上来避免队列满导致丢数据。收集线程只做收集，能够迅速清空队列，不会被阻塞
// 派发线程中可以进行耗时的任务而不会导致netlink队列满而丢数据
class CKernelConnector : public IKernelConnector {
   public:
    CKernelConnector();
    // IKernelConnector interface
    virtual ~CKernelConnector();
    virtual void Release();
    virtual int Init();

    virtual int SetProtocol(int port);
    virtual int SetDriverPath(const char *path, int nForce);

    virtual int RegCmdHandler(const char* module, NLPolicyType cmd,
                              int priority, KernelCmdHandler handler,
                              void* para);
    virtual void UnRegCmdHandler(const char* module, NLPolicyType cmd);
    virtual int SendMsgKBuf(NLPolicyType cmd, void* buffer, int size);
    virtual int RegisterProduct(NL_PRODUCTION product);
    virtual int UnregisterProduct(NL_PRODUCTION product);
    virtual int EndWaiting(void* pwait_flag);
    virtual int EndBoolWaiting(void* pwait_flag, int bBool);
    virtual int SetChrDevName(const char* cdev_name);
    virtual int SetConfFile(const char* conf_file);

public:
    int GetMode();
	int DoRecvKylinMsg(void* pdata);
    int AddRef();

private:
	int handleEchoCmd(IKernelMsg* kernel_msg);
    int handleMsg(NLPolicyType cmd, IKernelMsg* rec_kernel_msg);
    int sendEchoStrMsg(const char* str);
    
    int initInner();
    void uninit();
    void initLSM();

    // init m_handlers
    int initCmdHandlers();
    void uninitCmdHandlers();

    int initKTransferProxy();
    void uninitKTransferProxy();

    int initDispatchThreads();
    void uninitDispatchThreads();

    void* dispatchFun(void*);
	int dispatchKylinMsg(struct kosecs_msg_data* msg);

    void initConfFile();
    void loadConfFile(int& log_level,std::string& log_path);
    void initLog(int log_level,const std::string& log_path);
    int setLogInfo(ASLogLevel level, const char* log_path);
    void trySetDebugLog();
    int sendLSMSymsToKernel(void);
	
	void mayStartWhiteBoxTest();

private:
    std::vector<CKCmdHandlers*> m_handlers;

    int m_ref_cnt;
    int m_init_status;  // 0-未初始化 1-初始化完成 2-初始化中

    int m_nProtocol; //netlink protocol
    std::string m_cdevName; //charater device name
    int m_nForce;
    std::string m_driverPath;
    std::string m_confFile;

    CKTransferProxy* m_proxy;
	bool m_whiteBoxTest; //是否正在进行白盒测试

    QH_THREAD::CRwlock m_rwlock;
    CThreadSafeQueue<std::tr1::shared_ptr<void> > data_queue_;
    QH_THREAD::CWorkerThread dispatch_threads_[kDispatchThreadNum];
};

#endif  // KERNEL_CONNECTOR_H
