#ifndef CPU_LIMIT_CPU_LIMIT_MGR_H
#define CPU_LIMIT_CPU_LIMIT_MGR_H

#include <pthread.h>
#include <set>
#include "singleton.hpp"

class CpuLimitManager {
  public:
    CpuLimitManager():m_init(false){}
    ~CpuLimitManager(){}

    bool Init();
    void SyncStop();

    void SetCpuLimitMode(int mode);
    void AddThread(pthread_t thread);
    void DeleteThread(pthread_t thread);

    void SpeedCtrl();
    bool IsOk() { return m_init; }

  private:
    volatile unsigned int m_speed;
    std::set<pthread_t> m_threadset;
    pthread_mutex_t m_lock;
    bool m_init;
};

#endif /* CPU_LIMIT_CPU_LIMIT_MGR_H */
