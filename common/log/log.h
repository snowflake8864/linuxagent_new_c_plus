#ifndef LOG_LOG_HPP_
#define LOG_LOG_HPP_

#ifndef __stdcall
#define __stdcall
#endif

#include "ASFramework/ASLog.h"

#define DbgLog_Log(level, fmt, ...)\
{\
        IASLog * pLogger = CEntModuleDebug::GetModuleDebugger();\
        if (pLogger)\
        {\
            pLogger->WriteA(level, const_cast<char*>(fmt), ##__VA_ARGS__);\
        }\
}

#define LOG_ERROR_SELF(fmt,...) DbgLog_Log(ASLog_Level_Error,  "OSECLOGSEL--%4d--" fmt, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR_DEV(fmt,...)  DbgLog_Log(ASLog_Level_Error,  "OSELOGCDEV--%4d--" fmt, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR_SYS(fmt,...)  DbgLog_Log(ASLog_Level_Error,  "OSECLOGSYS--%4d--" fmt, __LINE__, ##__VA_ARGS__)

#ifndef LOG_ERROR
#define LOG_ERROR(fmt, ...) DbgLog_Log(ASLog_Level_Error,  "OSECLOG%4d--" fmt, __LINE__, ##__VA_ARGS__)
#endif

#ifndef LOG_WARN
#define LOG_WARN(fmt, ...)  DbgLog_Log(ASLog_Level_Warning,"OSECLOG%4d--" fmt, __LINE__, ##__VA_ARGS__)
#endif

#ifndef LOG_INFO
#define LOG_INFO(fmt, ...)  DbgLog_Log(ASLog_Level_Trace,  "OSECLOG%4d--" fmt, __LINE__, ##__VA_ARGS__)
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG(fmt, ...) DbgLog_Log(ASLog_Level_Debug,  "OSECLOG%4d--" fmt, __LINE__, ##__VA_ARGS__)
#endif

#ifndef LOG_TRACE
#define LOG_TRACE LOG_INFO
#endif

class CEntModuleDebug {
  public:
    static void SetModuleDebugger(IASLog * pDebugger) {
        m_pDebugger = pDebugger;
        m_pDebugger->AddRef();
    }
    static void ReleaseModuleDebugger() {
        if (NULL != m_pDebugger && 0 == m_pDebugger->Release()) {
            m_pDebugger = NULL;
        }
    }
    static IASLog * GetModuleDebugger() {
        return m_pDebugger;
    }
  private:
    static IASLog * m_pDebugger;
};

#endif /* LOG_LOG_H_ */
