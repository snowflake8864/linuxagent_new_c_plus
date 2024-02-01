#ifndef QH_THREAD_THREAD_KEY_H_
#define QH_THREAD_THREAD_KEY_H_

#include <pthread.h>

namespace QH_THREAD {
class CThreadKey
{
  public:
    CThreadKey() {
        pthread_key_create(&m_key_, NULL);
    }
    ~CThreadKey() {
        pthread_key_delete(m_key_);
    }

  public:
    pthread_key_t& get_key() {
        return m_key_;
    }

  private:
    pthread_key_t m_key_;
}; // CThreadKey
} // namespace

#endif /* QH_THREAD_THREAD_KEY_H_ */