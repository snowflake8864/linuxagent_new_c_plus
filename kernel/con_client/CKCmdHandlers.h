#ifndef CCMDHANDLERS_H
#define CCMDHANDLERS_H

#include <vector>
#include "qh_thread/thread.h"
#include "IKernelConnector.h"

class CKCmdHandlers {
public:
    CKCmdHandlers();
    ~CKCmdHandlers();

    int RegKCmdHandler(const char* module, int cmd,
                        int priority, KernelCmdHandler handler,
                        void* para);
    int UnRegKCmdHandler(const char* module, int cmd);
    int HandleKMsg(int cmd, IKernelMsg* recv_kmsg);

private:
    QH_THREAD::CRwlock m_locker;
    std::vector<void*> m_handlers;
};
#endif
