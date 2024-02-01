#include "debug/time_debug.h"

TimeDebug::TimeDebug() : m_is_started_(false) {}

int TimeDebug::Start() {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    if (m_is_started_) {
        return TIME_DEBUG_HAVE_STARTED;
    }
    gettimeofday(&m_start_time_, NULL);
    m_last_time_ = m_start_time_;
    m_is_started_ = true;
    return TIME_DEBUG_OK;
}

void TimeDebug::Stop() {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    m_is_started_ = false;
}

int TimeDebug::GetTimeFromStart(unsigned long& time, bool is_update_last) {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    if (!m_is_started_) {
        return TIME_DEBUG_HAVE_STOPED;
    }
    struct timeval cur;
    gettimeofday(&cur, NULL);
    time = GetIntervalTime(m_start_time_, cur);
    if (is_update_last) {
        m_last_time_ = cur;
    }
    return TIME_DEBUG_OK;
}

int TimeDebug::GetTimeFromLast(unsigned long& time, bool is_update_last) {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    if (!m_is_started_) {
        return TIME_DEBUG_HAVE_STOPED;
    }
    struct timeval cur;
    gettimeofday(&cur, NULL);
    time = GetIntervalTime(m_last_time_, cur);
    if (is_update_last) {
        m_last_time_ = cur;
    }
    return TIME_DEBUG_OK;
}

unsigned long TimeDebug::GetIntervalTime(struct timeval& begin,
                                         struct timeval& end) {
    return 1000000 * (end.tv_sec - begin.tv_sec) + end.tv_usec - begin.tv_usec;
}

int TimeDebugManager::Start(const char* name) {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    std::string name_str(name);
    std::map<std::string, TimeDebug>::iterator it =
        m_time_debug_map_.find(name_str);
    if (it == m_time_debug_map_.end()) {
        m_time_debug_map_[name_str] = TimeDebug();
        return m_time_debug_map_[name_str].Start();
    } else {
        return it->second.Start();
    }
}

int TimeDebugManager::Stop(const char* name) {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    std::string name_str(name);
    std::map<std::string, TimeDebug>::iterator it =
        m_time_debug_map_.find(name_str);
    if (it == m_time_debug_map_.end()) {
        return TIME_DEBUG_NOT_EXIST;
    } else {
        it->second.Stop();
        return TIME_DEBUG_OK;
    }
}

int TimeDebugManager::GetTimeFromStart(const char* name, unsigned long& time,
                                       bool is_update_last) {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    std::string name_str(name);
    std::map<std::string, TimeDebug>::iterator it =
        m_time_debug_map_.find(name_str);
    if (it == m_time_debug_map_.end()) {
        return TIME_DEBUG_NOT_EXIST;
    } else {
        return it->second.GetTimeFromStart(time, is_update_last);
    }
}

int TimeDebugManager::GetTimeFromLast(const char* name, unsigned long& time,
                                      bool is_update_last = true) {
    QH_THREAD::CMutexAutoLocker locker(&m_mutex_);
    std::string name_str(name);
    std::map<std::string, TimeDebug>::iterator it =
        m_time_debug_map_.find(name_str);
    if (it == m_time_debug_map_.end()) {
        return TIME_DEBUG_NOT_EXIST;
    } else {
        return it->second.GetTimeFromLast(time, is_update_last);
    }
}