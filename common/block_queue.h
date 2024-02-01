#ifndef BLCOKQUEUE_H_
#define BLCOKQUEUE_H_

#include <list>
#include <map>
#include <pthread.h>
#include <stdio.h>

template <typename key, typename value>
class CBlockQueue {
  public:
    CBlockQueue() {
        pthread_condattr_init(&condattr);
        pthread_condattr_setclock(&condattr,CLOCK_MONOTONIC);

        pthread_mutex_init(&lock, NULL);
        pthread_cond_init(&has_item, &condattr);
    }
    ~CBlockQueue() {
        pthread_mutex_destroy(&lock);
        pthread_cond_destroy(&has_item);
        pthread_condattr_destroy(&condattr);
    }

    void Lock() { pthread_mutex_lock(&lock); }
    void UnLock(){ pthread_mutex_unlock(&lock); }

    bool BEnQueue(key k, value* v) {
        bool bret = false;
        pthread_mutex_lock(&lock);
        bret = EnQueue(k, v);
        pthread_mutex_unlock(&lock);
        return bret;
    }

    bool EnQueue(key k, value* v) {
        if (m_safemap.find(k) != m_safemap.end())
            return false;

        m_safemap.insert(std::make_pair(k, v));
        return true;
    }

    void DeQueue(std::map<key, value*>& m) {
        if (pthread_mutex_trylock(&lock) == 0) {
            m_safemap.swap(m);
            m_safemap.clear();
            pthread_mutex_unlock(&lock);
        }
    }
    
    //wait time ms
    void Wait(long timeout) {
        pthread_mutex_lock(&lock);
        
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        long wait_time = ts.tv_nsec + (timeout*1000000);
        ts.tv_sec += (wait_time/1000000000);
        ts.tv_nsec = (wait_time%1000000000);
        
        pthread_cond_timedwait(&has_item, &lock, &ts);
        
        pthread_mutex_unlock(&lock);
    }

    void Signal() {
        pthread_mutex_lock(&lock);
        pthread_cond_broadcast(&has_item);
        pthread_mutex_unlock(&lock);
    }

  public:
    std::map<key, value*> m_safemap;
    // 对外公开的锁和条件变量，可用于等待队列非空
    pthread_condattr_t condattr;
    pthread_mutex_t lock;
    pthread_cond_t has_item;
};

#endif /* BLCOKQUEUE_H_ */
