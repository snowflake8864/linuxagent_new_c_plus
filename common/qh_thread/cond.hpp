#ifndef QH_THREAD_COND_HPP_
#define QH_THREAD_COND_HPP_

#include "qh_thread/mutex.hpp"
#include <time.h>

namespace QH_THREAD {
class CCond {
  public:
    CCond() {
        p_cmutex_ = NULL;
    }

    ~CCond() {
        pthread_condattr_destroy(&m_condattr_);
        pthread_cond_destroy(&m_cond_);
    }
  public:
    int Init(CMutex* mutex) {
        p_cmutex_ = mutex;
        pthread_condattr_init(&m_condattr_);
        pthread_condattr_setclock(&m_condattr_, CLOCK_MONOTONIC);
        return pthread_cond_init(&m_cond_, &m_condattr_);
    }

    int Signal() {
        return pthread_cond_signal(&m_cond_);
    }

    int BroadCast() {
        return pthread_cond_broadcast(&m_cond_);
    }

    int Wait() {
        return pthread_cond_wait(&m_cond_, p_cmutex_->get_mutex());
    }

    int WaitTimeoutSecond(int seconds) {
        struct timespec tv;
        if (seconds > 0) {
            clock_gettime(CLOCK_MONOTONIC, &tv);
            tv.tv_sec += seconds;
            tv.tv_nsec = 0;
            return pthread_cond_timedwait(&m_cond_, p_cmutex_->get_mutex(), &tv);
        } else {
            return pthread_cond_wait(&m_cond_, p_cmutex_->get_mutex());
        }
    }

    int WaitTimeoutMilliSecond(long milliseconds) {
        struct timespec tv;
        if (milliseconds > 0) {
            clock_gettime(CLOCK_MONOTONIC, &tv);
            long wait_time = tv.tv_nsec + (milliseconds * 1000000);
            tv.tv_sec += (wait_time / 1000000000);
            tv.tv_nsec = (wait_time % 1000000000);
            return pthread_cond_timedwait(&m_cond_, p_cmutex_->get_mutex(), &tv);
        } else {
            return pthread_cond_wait(&m_cond_, p_cmutex_->get_mutex());
        }
    }

  private:
    CMutex * p_cmutex_;
    pthread_condattr_t m_condattr_;
    pthread_cond_t m_cond_;
}; // cond
} // namespace

#endif /* QH_THREAD_COND_HPP_ */