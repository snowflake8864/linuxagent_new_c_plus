#ifndef CKCONNECTOR_LOG_H
#define CKCONNECTOR_LOG_H
#include "log/log.h"
#include "singleton.hpp"

class CASLogImpl;
class CKConnectorLog
{
public:
    CKConnectorLog();
    ~CKConnectorLog();
    int Init();
    
    int isDebug();

    int SetLogLevel(ASLogLevel log_level);
    int SetLogPath(const char* log_path);
private:
    void uninit();;
private:
    ASLogLevel m_log_level;
    std::string log_path;
    CASLogImpl *m_pLogImpl;
};

#endif  // CKCONNECTOR_LOG_H
