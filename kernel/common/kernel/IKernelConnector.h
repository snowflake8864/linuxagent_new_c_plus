#ifndef IKERNEL_CONNECTOR_H
#define IKERNEL_CONNECTOR_H
#include <stdint.h>
#include <unistd.h>
#include "gnHead.h"
//#include "log/log.h"

typedef enum {
    KERNEL_CONNECTOR_ERROR_OK = 0,
    KERNEL_CONNECTOR_ERROR_FAIL,
    KERNEL_CONNECTOR_ERROR_ABORT,  // KernelCmdHandler注册函数返回此值表明禁止后续派发
    KERNEL_CONNECTOR_ERROR_INVALID_PARA,
    KERNEL_CONNECTOR_ERROR_MULTI_REG_CMD,
    KERNEL_CONNECTOR_ERROR_NOT_ROOT,
    KERNEL_CONNECTOR_ERROR_LOAD_MODULE,
    KERNEL_CONNECTOR_ERROR_SOCKET_ALLOC,
    KERNEL_CONNECTOR_ERROR_CONNECT,
    KERNEL_CONNECTOR_ERROR_RESOLVE,
    KERNEL_CONNECTOR_ERROR_MODIFY_CB,
    KERNEL_CONNECTOR_ERROR_DIVER_VER,
    KERNEL_CONNECTOR_ERROR_TIMEOUT,
    KERNEL_CONNECTOR_ERROR_INIT_MSG,
    KERNEL_CONNECTOR_ERROR_SET_ATTR,
    KERNEL_CONNECTOR_ERROR_SEND_MSG,
    KERNEL_CONNECTOR_ERROR_NOT_INIT,
    KERNEL_CONNECTOR_ERROR_INVALID_CMD,
    KERNEL_CONNECTOR_ERROR_NOMEM,
    KERNEL_CONNECTOR_ERROR_BAD_MSG,
} KERNEL_CONNECTOR_ERROR;

#define KERNEL_CONNECTRT_PRIORITY_CNT 5

#define KTQ_PRIORITY_CNT  KERNEL_CONNECTRT_PRIORITY_CNT

//错误码太长了，受不了，重定义短一些
#define KTQ_OK          KERNEL_CONNECTOR_ERROR_OK
#define KTQ_EFAIL       KERNEL_CONNECTOR_ERROR_FAIL
// KernelCmdHandler注册函数返回此值表明禁止后续派发
#define KTQ_EABORT      KERNEL_CONNECTOR_ERROR_ABORT 
//invalid arguments
#define KTQ_EINVAL      KERNEL_CONNECTOR_ERROR_INVALID_PARA
//duplicate cmd handler
#define KTQ_EDUPCMD     KERNEL_CONNECTOR_ERROR_MULTI_REG_CMD
#define KTQ_ENOTROOT    KERNEL_CONNECTOR_ERROR_NOT_ROOT
#define KTQ_EBADMOD     KERNEL_CONNECTOR_ERROR_LOAD_MODULE
#define KTQ_EALLOCSOCK  KERNEL_CONNECTOR_ERROR_SOCKET_ALLOC
#define KTQ_ECONNECT    KERNEL_CONNECTOR_ERROR_CONNECT
#define KTQ_EFAMILY     KERNEL_CONNECTOR_ERROR_RESOLVE
#define KTQ_EBADCB      KERNEL_CONNECTOR_ERROR_MODIFY_CB
#define KTQ_EBADKVER    KERNEL_CONNECTOR_ERROR_DIVER_VER
#define KTQ_ETIMEOUT    KERNEL_CONNECTOR_ERROR_TIMEOUT
#define KTQ_EINITMSG    KERNEL_CONNECTOR_ERROR_INIT_MSG
//set attributed failed
#define KTQ_ESETATTR    KERNEL_CONNECTOR_ERROR_SET_ATTR 
#define KTQ_ESENDMSG    KERNEL_CONNECTOR_ERROR_SEND_MSG
#define KTQ_ENOTINIT    KERNEL_CONNECTOR_ERROR_NOT_INIT
//bad cmd
#define KTQ_EBADCMD     KERNEL_CONNECTOR_ERROR_INVALID_CMD
#define KTQ_ENOMEM      KERNEL_CONNECTOR_ERROR_NOMEM
#define KTQ_EBADMSG     KERNEL_CONNECTOR_ERROR_BAD_MSG


class IKernelMsg;
class IKernelConnector;

/*
 * return KERNEL_CONNECTOR_ERROR_ABORT will abort dispatch
 * if *p_send_kernel_msg != NULL, then send msg to kernel in the end of dispatch
 * KernelConnect delete *p_send_kernel_msg itself, do not double free
 */
typedef int (*KernelCmdHandler)(NLPolicyType cmd, IKernelMsg* rec_kernel_msg,
                                void* para);

#ifndef FCreateInstance_defined
typedef void (*FCreateInstance)(IKernelConnector** pKernelConnector);
#define FCreateInstance_defined
#endif

extern "C" void CreateInstance(IKernelConnector** pKernelConnector);

class IKernelMsg {
   public:
    virtual ~IKernelMsg(){};
    virtual const char* GetAttrMsg(NL_POLICY_ATTR attr_index,
                                   size_t& msg_len) = 0;
};

class IKernelConnector {
   public:
    virtual ~IKernelConnector(){};
    virtual void Release() = 0;

    virtual int Init() = 0;
    virtual int RegisterProduct(NL_PRODUCTION production_type) = 0;
    virtual int SetProtocol(int port) = 0;
    virtual int SetDriverPath(const char *path, int nForce) = 0;
    //virtual int SetLogInfo(ASLogLevel level, const char* log_path) = 0;

    // reg NL_POLICY_CMD_ECHO will fail because it is can only used by
    // KernelConnector
    virtual int RegCmdHandler(const char* reg_module_name, NLPolicyType cmd,
                              int priority, KernelCmdHandler handler,
                              void* para) = 0;
    virtual void UnRegCmdHandler(const char* reg_module_name,
                                 NLPolicyType cmd) = 0;
    virtual int SendMsgKBuf(NLPolicyType cmd, void* buffer, int size) = 0;

    virtual int EndWaiting(void* pwait_flag) = 0;
    virtual int EndBoolWaiting(void* pwait_flag, int bBool) = 0;
    virtual int SetChrDevName(const char* cdev_name) { return 0; } 
    virtual int SetConfFile(const char* conf_file) { return 0; }
    virtual int UnregisterProduct(NL_PRODUCTION product) { return 0; }
};

#endif  // IKERNEL_CONNECTOR_H
