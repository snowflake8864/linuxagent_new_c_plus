#include <algorithm>
#include <new>
#include <string>
#include <list>
#include "gnHead.h"
#include "CKernelConnector.h"
#include "CKCmdHandlers.h"

struct KHandlerInfo {
    KHandlerInfo(const char* module, int _cmd, int _priority,
            KernelCmdHandler _handler, void* _arg)
        :cmd(_cmd)
        ,priority(_priority)
        ,module_name(module)
        ,handler(_handler)
        ,para(_arg)
        {}

    int cmd;
    int priority;
    std::string module_name;
    KernelCmdHandler handler;
    void* para;
};

//同一个模块中只允许对一个命令注册一个handler
bool operator==(const KHandlerInfo& left,const KHandlerInfo& right)
{
    return ((left.module_name == right.module_name) &&
            (left.cmd == right.cmd));
}

typedef std::list<KHandlerInfo> CKHandlerList;


CKCmdHandlers::CKCmdHandlers()
{
    CKHandlerList* pList = NULL;
    m_handlers.resize(KTQ_PRIORITY_CNT,NULL);
    for(size_t i = 0;i < KTQ_PRIORITY_CNT;i++) {
        pList = new CKHandlerList;
        m_handlers[i] = pList;
    }
}

CKCmdHandlers::~CKCmdHandlers()
{
    CKHandlerList* pList = NULL;
    for(size_t i = 0;i < KTQ_PRIORITY_CNT;i++) {
        pList = (CKHandlerList*)m_handlers[i];
        delete pList;
    }
    m_handlers.clear();
}

int CKCmdHandlers::RegKCmdHandler(const char* module,
                                    int cmd, int priority,
                                    KernelCmdHandler cmdHandler, void* arg)
{

    int rc = KTQ_EINVAL;
    if (!module || !cmdHandler || cmd < NL_POLICY_CMD_NOTIFY ||
        cmd >= NL_MAX_INDEX || priority < 0 ||
        priority >= KTQ_PRIORITY_CNT ||
        cmd == NL_POLICY_CMD_ECHO)
    {
        LOG_ERROR("OsecCmdHandler failed, invalid arg, module=%s, cmd=%d, "
            "priority=%d, KCmdHandler=%x",
            module, cmd, priority, cmdHandler);
        return rc;
    }

    rc = KTQ_EDUPCMD;
    {
        CKHandlerList::iterator it;
        CKHandlerList* pList = NULL;
        KHandlerInfo handler(module, cmd, priority, cmdHandler, arg);

        pList = (CKHandlerList*)m_handlers[priority];
        QH_THREAD::CWriteAutoLocker locker(&m_locker);
        it = std::find(pList->begin(),pList->end(),handler);
        if (it == pList->end()) {
            pList->push_back(handler);
            rc = KTQ_OK;
        }
    }

    if(rc) {
        //命令已注册
        LOG_WARN(
            "OsecCmdHandler failed, multiple register, module=%s, cmd=%d, "
            "priority=%d, KCmdHandler=%x",
            module, cmd, priority, cmdHandler);
    } else {
        LOG_INFO(
            "OsecCmdHandler success, module=%s, cmd=%d, "
            "priority=%d, KCmdHandler=%x",
            module, cmd, priority, cmdHandler);
    }
    return rc;
}

int CKCmdHandlers::UnRegKCmdHandler(const char* module,int cmd)
{
    int rc = KTQ_EBADCMD;
    CKHandlerList::iterator it;
    CKHandlerList* pList = NULL;
    KHandlerInfo handler(module, cmd, 0, NULL, NULL);

    for(size_t i = 0;i < m_handlers.size();i++) {
        pList = (CKHandlerList*)m_handlers[i];
        QH_THREAD::CWriteAutoLocker locker(&m_locker);
        it = std::find(pList->begin(),pList->end(),handler);
        if(it != pList->end()) {
            rc = KTQ_OK;
            pList->erase(it);
        }
    }

    if(rc == KTQ_OK) {
        LOG_INFO("UnRegKCmdHandler success, module=%s, cmd=%d",
                    module, cmd);
    } else {
        LOG_ERROR("UnOsecCmdHandler failed, module=%s, cmd=%d,"
                "not find cmd-handler",module, cmd);
    }

    return rc;
}

int CKCmdHandlers::HandleKMsg(int cmd, IKernelMsg* recv_kmsg)
{
    int rc = KTQ_OK;
    void* para = NULL;
    std::string modname;
    bool bdispatched = false;
    CKHandlerList::iterator it;
    CKHandlerList* pList = NULL;
    KernelCmdHandler handler = NULL;
    QH_THREAD::CReadManualLocker locker(&m_locker);

    //按优先级从0-KTQ_PRIORITY_CNT派发
    for(size_t i = 0;i < m_handlers.size();i++) {
        pList = (CKHandlerList*)m_handlers[i];
        
        locker.lock();
        for (it = pList->begin();it != pList->end(); ++it) {
            para = it->para;
            handler = it->handler;
            modname = it->module_name;
            locker.unlock();
            
            LOG_DEBUG("dispatch cmd %d to %p of module: %s",
                cmd,handler,modname.c_str());
            bdispatched = true;
            rc = handler(NLPolicyType(cmd), recv_kmsg,para);
            if (rc == KTQ_EABORT) { return rc; }

            locker.lock();
        }
        locker.unlock();
    }

    if(!bdispatched) {
        LOG_WARN("there is no handler "
            "for msg cmd: %d",cmd);
    }

    return rc;
}
