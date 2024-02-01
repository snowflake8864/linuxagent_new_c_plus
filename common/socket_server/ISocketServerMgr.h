#ifndef I_SOCKET_SERVER_MGR_H_
#define I_SOCKET_SERVER_MGR_H_

#include "common/ASFramework/ASUnknown.h"

class ISocketServerMgr;
typedef ISocketServerMgr* (*FCreateInstance)(const char* config_path);

class ISocketServerMgr : public IASUnknown {
  public:
    virtual ~ISocketServerMgr() {}

  public:
    virtual bool Init(const char* dst) = 0;
    virtual bool UnInit() = 0;

  public:
    virtual void RunLoop() = 0;
    virtual void StopLoop() = 0;
};

#endif /* I_SOCKET_SERVER_MGR_H_ */