#ifndef QH_THREAD_THREAD_H_
#define QH_THREAD_THREAD_H_

#include <tr1/functional>
#include <tr1/memory>
#include "qh_thread/locker.hpp"

namespace QH_THREAD {
typedef std::tr1::shared_ptr<CMutexAutoLocker> PauseQuitHelperAutoLocker;

class CPauseQuitHelper {
  public:
    enum LOCK_TYPE {
        NEED_LOCK = 0,
        NO_NEED_LOCK,
    };
    CPauseQuitHelper();
    ~CPauseQuitHelper(){};
    void Reset(LOCK_TYPE lock_type = NEED_LOCK);
    void Pause();
    void Quit();
    void Signal();
    void Resume();
    bool IsQuit();
    bool IsPause();
    // if pause then wait untill resume or quit called, return isQuit()
    bool DoPauseOrQuit();
    // wait second untill timeout resume or quit called, return isQuit(), second less than 0 then wait forever
    bool DoWaitOrQuit(int second = -1);
    void Lock();
    void Unlock();
    PauseQuitHelperAutoLocker GetAutoLocker();

  private:
    volatile bool m_is_quit_;
    volatile bool m_is_pause_;
    CMutex m_mutex_;
    CCond m_cond_;
}; // CPauseQuitHelper

class CThread {
  public:
    CThread();
    virtual ~CThread(){};

  public:
    int join();
    int tryjoin_np();
    int detach();
    int run(void* param);
    void* get_param();
    virtual void quit();
    virtual void pause();
    virtual void resume();
    virtual void signal();
    bool isRunning();
    bool isQuit();
    bool isPause();
    bool isRealQuit();
    pthread_t getThreadId() { return m_hthread_; }

    virtual void PreAction(){};
    virtual void PostAction(){};

  protected:
    virtual void* thread_function(void* param) = 0;
    // if pause then wait untill resume or quit called, return isQuit()
    bool doPauseOrQuit();
    bool doWaitOrQuit(int second = -1);

  private:
    pthread_t m_hthread_;
    void* p_param_;
    static void* private_thread_func(void* this_ptr);
    volatile bool m_valid_thread_id_;
    CPauseQuitHelper m_pause_quit_helper_;
}; // CThread

class CWorkerThread {
  public:
    typedef std::tr1::function<void*(void*)> ThreadFunc;

    CWorkerThread();
    CWorkerThread(ThreadFunc thread_func);
    ~CWorkerThread() {};

  public:
    int Join();
    int TryjoinNp();
    int Detach();
    int Run(void* param);
    void* GetParam();
    void Quit();
    void Pause();
    void Resume();
    bool IsRunning();
    bool IsQuit();
    bool IsPause();
    bool IsRealQuit();
    void SetThreadFunc(ThreadFunc thread_func) { p_thread_fun_ = thread_func; }
    pthread_t GetThreadId() { return m_thread_handle_; }

    virtual void PreAction(){};
    virtual void PostAction(){};

    bool DoPauseOrQuit();
    bool DoWaitOrQuit(int second = -1);

  private:
    static void* PrivateThreadFunc(void* this_ptr);

  private:
    pthread_t m_thread_handle_;
    void* m_param_;
    bool m_is_valid_thread_id_;
    CPauseQuitHelper m_pause_quit_helper_;
    ThreadFunc p_thread_fun_;
}; // CWorkerThread
} // namespace


#endif /* QH_THREAD_THREAD_H_ */