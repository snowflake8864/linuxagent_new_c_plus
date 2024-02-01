#ifndef _SOCKET_UTILS_H
#define _SOCKET_UTILS_H

#include "common/socket/socket_utils.h"

class ISocketClientMgr;

namespace socket_control {
    std::string GetProcessStringName(ProcessName process_name);
    ProcessName GetProcessName(const std::string& str_process);
    long GetFunctionTimeOut(const std::string& str_function);

    int SyncSendDataToOtherProcess(ISocketClientMgr *pSocketClientMgr, const std::string& str_content, const char *lpSender, const char *lpRecver, const char *lpFunction, std::string& recv_content);
    void AsyncSendDataToOtherProcess(ISocketClientMgr *pSocketClientMgr, const std::string& str_content, const char *lpSender, const char *lpRecver, const char *lpFunction);
    void ResponseCallFunc(ISocketClientMgr *pSocketClientMgr, const std::string &strResponse, const UnixSocketData &recvData);
}

#endif
