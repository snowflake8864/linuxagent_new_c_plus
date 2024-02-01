#ifndef DEBUG_TIME_DEBUG_H_
#define DEBUG_TIME_DEBUG_H_

#include <sys/time.h>
#include <map>
#include <string>
#include "qh_thread/locker.hpp"
#include "singleton.hpp"
#include "log/log.h"

enum TIME_DEBUG_ERROR {
    TIME_DEBUG_OK = 0,
    TIME_DEBUG_HAVE_STARTED,
    TIME_DEBUG_HAVE_STOPED,
    TIME_DEBUG_NOT_EXIST
};

class TimeDebug {
   public:
    TimeDebug();
    int Start();
    void Stop();
    int GetTimeFromStart(unsigned long& time, bool is_update_last);
    int GetTimeFromLast(unsigned long& time, bool is_update_last);

   private:
    inline unsigned long GetIntervalTime(struct timeval& begin,
                                         struct timeval& end);
    bool m_is_started_;
    struct timeval m_start_time_;
    struct timeval m_last_time_;
    QH_THREAD::CMutex m_mutex_;
};

class TimeDebugManager : public Singleton<TimeDebugManager> {
   public:
    int Start(const char* name);
    int Stop(const char* name);
    int GetTimeFromStart(const char* name, unsigned long& time,
                         bool is_update_last);
    int GetTimeFromLast(const char* name, unsigned long& time,
                        bool is_update_last);

   private:
    std::map<std::string, TimeDebug> m_time_debug_map_;
    QH_THREAD::CMutex m_mutex_;
};

#ifdef DEBUG
#define GENERATE_LOCAL_TIME_DEBUG TimeDebug time_debug;
#define TIME_DEBUG_START time_debug.Start();
#define TIME_DEBUG_STOP time_debug.Stop();
#define TIME_DEBUG_GET_TIME_FROM_START(event, is_update_last)         \
    {                                                                 \
        unsigned long time = 0;                                       \
        int code = time_debug.GetTimeFromStart(time, is_update_last); \
        if (code != TIME_DEBUG_OK) {                                  \
            LOG_DEBUG("GetTimeFromStart failed with code %d", code);  \
        } else {                                                      \
            LOG_DEBUG("%s run for %lu us", event, time);              \
        }                                                             \
    }
#define TIME_DEBUG_GET_TIME_FROM_LAST(event, is_update_last)         \
    {                                                                \
        unsigned long time = 0;                                      \
        int code = time_debug.GetTimeFromLast(time, is_update_last); \
        if (code != TIME_DEBUG_OK) {                                 \
            LOG_DEBUG("GetTimeFromLast failed with code %d", code);  \
        } else {                                                     \
            LOG_DEBUG("%s run for %lu us", event, time);             \
        }                                                            \
    }
#define TIME_DEBUG_LOG(fmt, args...) LOG_DEBUG(fmt, ##args)

#else
#define GENERATE_LOCAL_TIME_DEBUG
#define TIME_DEBUG_START
#define TIME_DEBUG_STOP
#define TIME_DEBUG_GET_TIME_FROM_START(time, is_update_last)
#define TIME_DEBUG_GET_TIME_FROM_LAST(time, is_update_last)
#define TIME_DEBUG_LOG(fmt, args...)
#endif  // DEBUG

#endif  /* DEBUG_TIME_DEBUG_H_ */