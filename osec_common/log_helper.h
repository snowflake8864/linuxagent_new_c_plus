#ifndef LOG_HELPER_H
#define LOG_HELPER_H


#include <string>
#include <string.h>

class CASLogImpl;
class ITimer;

class CLogHelper
{
public:
    CLogHelper();
    ~CLogHelper();

    int initByConfig(std::string strConfigPath);
    int initByCustom(int logLevel, int logMaxSize, const std::string &strLogPath, const std::string &strLogBackupPath);

private:
    int initLog();

private:
    int m_nLogLevel;
    int m_nLogSize;
    std::string m_strLogPath;
    std::string m_strLogBackupPath;
    CASLogImpl *m_pLogImpl;
    ITimer *m_pTimer;
};


#endif