#include "ini_parser.h"
#include <unistd.h>

#include "CKConnectorLog.h"
#include "ASFramework/util/ASLogImpl.h"


int CKConnectorLog::Init()
{
    m_pLogImpl = new CASLogImpl();
    if (m_pLogImpl == NULL) {
        return -1;
    }
    m_pLogImpl->SetLogFilePath(log_path.c_str());
    m_pLogImpl->SetLogMaxSize(10*1024*1024);
    m_pLogImpl->SetLogLevel(m_log_level);
    m_pLogImpl->Open();

    CEntModuleDebug::SetModuleDebugger(m_pLogImpl);
    LOG_INFO("Init done");
    return 0;
}

void CKConnectorLog::uninit()
{
    if (m_pLogImpl) {
        m_pLogImpl->Close();
        m_pLogImpl->UnInit();
		delete m_pLogImpl;
		m_pLogImpl = NULL;
    }
}

int CKConnectorLog::SetLogLevel(ASLogLevel  level)
{
    m_log_level = level;
    if (m_pLogImpl) {
        m_pLogImpl->SetLogLevel(m_log_level);
    }
    return 0;
}

CKConnectorLog::CKConnectorLog()
{
    char buf[1024] = {0};

    m_pLogImpl = NULL;
    m_log_level = ASLog_Level_Trace;
    
    ::getcwd(buf,sizeof(buf));
    log_path = std::string(buf) + "/Log/OsecKernel.log";
}

CKConnectorLog::~CKConnectorLog() 
{
    uninit();
}

int CKConnectorLog::SetLogPath(const char* log_path)
{
    this->log_path = log_path;
    return 0;
}

int CKConnectorLog::isDebug()
{
    return m_log_level == ASLog_Level_Debug;
}
