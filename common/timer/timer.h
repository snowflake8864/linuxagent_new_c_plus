#ifndef TIMER_TIMER_H_
#define TIMER_TIMER_H_

#include <map>
#include <queue>
#include <string>
#include "timer/timer_interface.hpp"
#include "qh_thread/multi_thread.h"
#include "log/log.h"

#define DEFAULT_TASK_WORKER_SIZE 1

class CTaskWorker : public QH_THREAD::CMultiThread {
  public:
    CTaskWorker(int size);
    ~CTaskWorker();

  public:
    void AddTask(TimerHandler taskinfo);

  protected:
    virtual void *thread_function(void *param);

  private:
    QH_THREAD::CMutex m_queue_mutex_;
    std::queue<TimerHandler> m_task_queue_;
};

class CTimer : public ITimer, public QH_THREAD::CThread {
  
  ASUNKNOWN_EASY_IMPLEMENT(CTimer)

  public:
    CTimer();
    virtual ~CTimer();

  public:
    virtual int RegisterEvent(TimerHandlerConf stConf, const std::string &strTimerName);
    virtual int RefreshTimer(TimerHandlerConf stConf, const std::string strTimerName);
    virtual int UnRegisterEvent(const std::string &strTimerName);

  protected:
    virtual void *thread_function(void *param) { TimerLoop(); return NULL; }

  private:
    void TimerLoop();

  private:
    QH_THREAD::CMutex m_muxlck_;
    std::map<std::string, TimerHandlerConf> m_eventsmap_;
    volatile int m_click_time_;
    CTaskWorker *p_task_worker_;
};

#endif /* TIMER_TIMER_H_ */
