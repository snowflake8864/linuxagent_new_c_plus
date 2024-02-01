#ifndef I_SOCKET_CLIENT_MGR_H_
#define I_SOCKET_CLIENT_MGR_H_

#include "common/socket/socket_process_info.h"
#include "common/ASFramework/ASUnknown.h"

namespace SocketCallBackType {
    const long SOCKET_CLIENT_CALLBACK_TYPE_UNKNOWN = -1;
    // 通信客户端内部发生核心错误
    const long SOCKET_CLIENT_CALLBACK_TYPE_CORE_ERROR = 0;
    // 通信客户端检测通信服务端退出信号
    const long SOCKET_CLIENT_CALLBACK_TYPE_SERVER_EXIT = 1;
    // 通信客户端重新连接通信服务端信号
    const long SOCKET_CLIENT_CALLBACK_TYPE_CONNECTED = 2;
};
using namespace SocketCallBackType;

namespace SocketClient {
    // 通信客户端SDK内部错误码，此字段暂时不使用
    const char* const SOCKET_CLIENT_ERROR_CODE = "socket.client.error.code";
    // 通信客户端SDK内部错误信息
    const char* const SOCKET_CLIENT_ERROR_MSG = "socket.client.error.msg";
    // 通信客户端SDK回调函数类型
    const char* const SOCKET_CLIENT_CALLBACK_TYPE = "socket.client.callback.type";
    // 通信客户端SDK回调函数入口
    const char* const SOCKET_CLIENT_CALLBACK = "socket.client.cb";
};
using namespace SocketClient;

class IASBundle;

class ISocketCallBackReceiver {
  public:
    virtual void OnCallBack(IASBundle* p_bundle) = 0;
};

class IEntBase {
  public:
    virtual void RecvData(IASBundle* p_bundle) = 0;
};

class ISocketClientMgr;

#ifndef FCreateInstance_defined
typedef ISocketClientMgr* (*FCreateInstance)(const char* config_path);
#define FCreateInstance_defined
#endif

class ISocketClientMgr : public IASUnknown {
  public:
    virtual ~ISocketClientMgr() {}

  public:
    virtual bool Init(const char* dst) = 0;
    virtual bool UnInit() = 0;

  public:
    virtual void Run() = 0;
    virtual bool ConnectSocket(const char* process_name) = 0;
    virtual bool DestroySocketConnect() = 0;
    virtual bool ReconnectSocket(const char* process_name) = 0;

  public:
    virtual void RegisterService(const char* service, IEntBase* p_ent) = 0;
    virtual void RegisterRecvFunc(const char* service, const char* function) = 0;
    virtual void RegisterInterestedFunc(const char* function, const char* process_name = PROCESS_UNKNOWN_NAME, unsigned int timeout = 10 * 1000) = 0;
    virtual void RegisterCallBackReceiver(IASBundle* p_cb) = 0;

  public:
    virtual void SyncSendData(const char* str_send, IASBundle* &recv_data) = 0;
    virtual void ASyncSendData(const char* str_send) = 0;
};

#endif /* I_SOCKET_CLIENT_MGR_H_ */