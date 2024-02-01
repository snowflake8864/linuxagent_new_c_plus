#ifndef QH_THREAD_MUTEXT_HPP_
#define QH_THREAD_MUTEXT_HPP_

#include <pthread.h>

namespace QH_THREAD {
class CMutex {
  public:
    CMutex() {
        m_error_num_ = pthread_mutex_init(&m_mutex_, NULL);
    }
    ~CMutex(){
        pthread_mutex_destroy(&m_mutex_);
    }

  public:
    int get_error() { return m_error_num_;}
    pthread_mutex_t * get_mutex() {
        return &m_mutex_;
    }

  private:
    int m_error_num_;
    pthread_mutex_t m_mutex_;
}; // CMutex
} // namespace
#endif /* QH_THREAD_MUTEXT_HPP_ */