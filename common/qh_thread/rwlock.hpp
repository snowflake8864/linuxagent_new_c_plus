#ifndef QH_THREAD_RWLOCK_HPP_
#define QH_THREAD_RWLOCK_HPP_

#include <pthread.h>

namespace QH_THREAD {
class CRwlock {
  public:
    CRwlock() {
        m_error_num_ = pthread_rwlock_init(&m_rwlock_, NULL);
    }
    ~CRwlock() {
        pthread_rwlock_destroy(&m_rwlock_);
    }

  public:
    int get_error() { return m_error_num_;}

    pthread_rwlock_t * get_lock() {
        return &m_rwlock_;
    }

  private:
    int m_error_num_;
    pthread_rwlock_t m_rwlock_;
}; // CRWlock
} // namespace
#endif /* QH_THREAD_RWLOCK_HPP_ */