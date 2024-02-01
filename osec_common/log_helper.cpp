#include "osec_common/log_helper.h"
#include "common/utils/file_utils.h"
#include "common/timer/timer.h"
#include "common/ASFramework/util/ASJsonWrapper.h"
#include "common/ASFramework/util/ASLogImpl.h"

CLogHelper::CLogHelper()
{
    m_nLogLevel = 2;
    m_nLogSize = 10 * 1024 * 1024;
    m_pLogImpl = NULL;
    m_pTimer = NULL;
}

CLogHelper::~CLogHelper()
{
    if (m_pTimer) {
        m_pTimer->Release();
    }
    if (m_pLogImpl) {
        m_pLogImpl->Release();
    }
}

int CLogHelper::initByConfig(std::string strConfigPath)
{
    if (strConfigPath.empty() || !file_utils::IsExist(strConfigPath)) {
        return -1;
    }
    Json::Value jvRoot;
    if (!CASJsonWrapper::LoadJsonFile(strConfigPath.c_str(), jvRoot)) {
        return -1;
    }
    m_nLogLevel = CASJsonWrapper::GetJsonValueInt("log_level", jvRoot, 2);
    m_nLogSize = CASJsonWrapper::GetJsonValueInt("log_size", jvRoot, 10 * 1024 * 1024);
    m_strLogPath = CASJsonWrapper::GetJsonValueString("log_path", jvRoot);
    m_strLogBackupPath = CASJsonWrapper::GetJsonValueString("log_backup_path", jvRoot);
    return initLog();
}

int CLogHelper::initByCustom(int logLevel, int logMaxSize, const std::string &strLogPath, const std::string &strLogBackupPath)
{
    m_nLogLevel = logLevel;
    m_nLogSize = logMaxSize;
    m_strLogPath = strLogPath;
    m_strLogBackupPath = strLogBackupPath;
    return initLog();
}

int CLogHelper::initLog()
{
    if (m_pTimer == NULL) {
        m_pTimer = new (std::nothrow) CTimer;
        if (m_pTimer == NULL) {
            return -1;
        }
        m_pTimer->AddRef();
    }
    
    if (m_pLogImpl == NULL) {
        m_pLogImpl = new (std::nothrow) CASLogImpl;
        if (m_pLogImpl == NULL) {
            return -1;
        }
        m_pLogImpl->AddRef();
    }
    
    m_pLogImpl->SetLogFilePath(m_strLogPath.c_str());
    m_pLogImpl->SetLogMaxSize(m_nLogSize);
    if (!m_strLogBackupPath.empty()) {
        m_pLogImpl->SetBackUp(m_pTimer);
        m_pLogImpl->SetBackupFilePath(m_strLogBackupPath.c_str());
    }
    m_pLogImpl->SetLogLevel((ASLogLevel)m_nLogLevel);
    m_pLogImpl->Init();
    CEntModuleDebug::SetModuleDebugger(m_pLogImpl);
    return 0;
}
