#ifndef QH_THREAD_MULTI_THREAD_H_
#define QH_THREAD_MULTI_THREAD_H_

#include "qh_thread/thread.h"
#include "cpu_limit/cpu_limit_mgr.h"
#include "singleton.hpp"

namespace QH_THREAD {
class CMultiThread {
  public:
    CMultiThread();
    virtual ~CMultiThread() { Release(); }

  public:
    bool Run();
    virtual void AsynStop();
    virtual void SynStop();
    virtual long Release();
    void SetConcurrentSize(int size);
    int GetConcurrentSize();
    bool IsCancelled();
    bool IsRunning();
    bool IsPause();
    virtual void Pause();
    virtual void Resume();
    void GetThreadId(pthread_t** thread, int* size);

  protected:
    // if pause then wait untill resume or quit called, return isQuit()
    bool DoPauseOrQuit();
    virtual void* thread_function(void* param) = 0;

    virtual void AddCpuLimit(pthread_t tid) {
      Singleton<CpuLimitManager>::Instance().AddThread(tid);
    }
    virtual void RemoveCpuLimit(pthread_t tid) {
      Singleton<CpuLimitManager>::Instance().DeleteThread(tid);
    }

  private:
    static void* private_thread_func(void* this_ptr);
    void SynStopByCount(int thread_count);

    int concurrent_size_;
    pthread_t* pthread_array_;
    CPauseQuitHelper pause_quit_helper_;
    CMutex lock_;
}; // CMultiThread
} // namespace

#endif /* QH_THREAD_MULTI_THREAD_H_ */