#ifndef SOCKET_SOCKET_PROCESS_INFO_H_
#define SOCKET_SOCKET_PROCESS_INFO_H_

#include <string>
#include <string.h>

namespace SocketProcessNameID {
    const long PROCESS_UNKNOWN_ID = -1; // 未知
};
#define ProcessName long
using namespace SocketProcessNameID;

namespace SocketProcessNameStr {
    const char* const PROCESS_UNKNOWN_NAME = "socket.*.name.unknown"; // 未知
};
using namespace SocketProcessNameStr;

namespace SocketProcessUniqueID {
    const char* const PROCESS_UNIQUE_ID = "socket.*.unique_id.unknown"; // 未知
};
using namespace SocketProcessUniqueID;

namespace RegisterFunctionStr {
    const char* const AK_REGISTER_FUNCTION_CLIENT_LOGIN = "socket.*.cmd.login"; // cmd login
};
using namespace RegisterFunctionStr;

#define UnixSocketKeyDataSender     "sender"   // 发送方
#define UnixSocketKeyDataRecver     "recver"   // 接收方
#define UnixSocketKeyDataPriority   "priority" // 优先级别，最高优先级0
#define UnixSocketKeyDataContent    "content"  // 数据内容
#define UnixSocketKeyDataContLen    "contlen"  // 数据长度
#define UnixSocketKeyDataFunction   "function" // 事件名称
#define UnixSocketKeyDataResponed   "responed" // 是否同步事件的回复
#define UnixSocketKeyDataUniqueID   "uuid"     // 消息唯一ID

#define ReServerFunctionLogin       "cmd_client_login"

struct UnixSocketData {
    UnixSocketData() {
        lpContent = NULL;
        nContLen = 0;
        nPriority = 0;
        bResponse = false;
    }
    void clone(UnixSocketData& Other) {
        Other.lpContent = (unsigned char *)(new(std::nothrow) char[nContLen]);
        if (Other.lpContent) {
            strncpy((char *)Other.lpContent, (char *)lpContent, nContLen);
            Other.nContLen = nContLen;
        } else {
            Other.nContLen = 0;
        }
        Other.strReciever = strReciever;
        Other.strSender = strSender;
        Other.strUUID = strUUID;
        Other.strFunction = strFunction;
        Other.nPriority = nPriority;
        Other.bResponse = bResponse;
    }
    void clear() {
        if (lpContent != NULL) { delete [] lpContent; lpContent = NULL; }
    }
    unsigned char * lpContent;
    std::string strReciever;
    std::string strSender;
    std::string strUUID;
    std::string strFunction;
    unsigned int nContLen;
    unsigned int nPriority;
    bool bResponse;
};

#endif /* SOCKET_SOCKET_PROCESS_INFO_H_ */