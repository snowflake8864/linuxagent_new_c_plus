#ifndef SINGLETON_HPP_
#define SINGLETON_HPP_

#include <pthread.h>
#include <new>

template <typename T>
class Singleton {
  public:
    static T& Instance() {
        Init();
        return *p_instance_;
    }

    static bool Init() {
        if (p_instance_ == NULL) {
            pthread_mutex_lock(&m_mutex_);
            if (p_instance_ == NULL) {
                p_instance_ = new (std::nothrow) T;
            }
            pthread_mutex_unlock(&m_mutex_);
        }
        return p_instance_ != NULL;
    }

    static void Uninit() {
        pthread_mutex_lock(&m_mutex_);
        if (p_instance_ != NULL) {
            delete p_instance_;
            p_instance_ = NULL;
        }
        pthread_mutex_unlock(&m_mutex_);
    }

  private:
    Singleton();
    Singleton(const Singleton&);
    ~Singleton();
    Singleton& operator=(const Singleton&);

  private:
    static T* volatile p_instance_;
    static pthread_mutex_t m_mutex_;
};

template <typename T>
T* volatile Singleton<T>::p_instance_ = NULL;
template <typename T>
pthread_mutex_t Singleton<T>::m_mutex_ = PTHREAD_MUTEX_INITIALIZER;

#endif /* SINGLETON_HPP_ */