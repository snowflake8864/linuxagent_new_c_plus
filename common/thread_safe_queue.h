#ifndef THREAD_SAFE_QUEUE_H_
#define THREAD_SAFE_QUEUE_H_

#include <pthread.h>
#include <stdio.h>
#include <list>
#include <queue>

template <typename T>
class CThreadSafeQueue {
   public:
    CThreadSafeQueue() {
        pthread_condattr_init(&condattr);
        pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);

        pthread_mutex_init(&lock, NULL);
        pthread_cond_init(&has_item, &condattr);
    }
    ~CThreadSafeQueue() {
        pthread_mutex_destroy(&lock);
        pthread_cond_destroy(&has_item);
        pthread_condattr_destroy(&condattr);
    }

    void EnQueue(T value) {
        Lock();
        if (queue_.size() < maxSize) {
            queue_.push(value);
            SignalWithHoldLock();
        }
        Unlock();
        return;
    }

    bool DeQueue(T& value, long timeout_ms) {
        Lock();
        if (queue_.empty()) {
            WaitWithHokdLock(timeout_ms);
        }
        if (queue_.empty()) {
            Unlock();
            return false;
        } else {
            value = queue_.front();
            queue_.pop();
            Unlock();
            return true;
        }
    }

    bool TryDeQueue(T& value) {
        if (TryLock()) {
            value = queue_.front();
            queue_.pop();
            Unlock();
            return true;
        } else {
            return false;
        }
    }

    // wait time ms
    void Wait(long timeout_ms) {
        Lock();
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        long wait_time = ts.tv_nsec + (timeout_ms * 1000000);
        ts.tv_sec += (wait_time / 1000000000);
        ts.tv_nsec = (wait_time % 1000000000);

        pthread_cond_timedwait(&has_item, &lock, &ts);
        Unlock();
    }

    void BroadCast() {
        Lock();
        pthread_cond_broadcast(&has_item);
        Unlock();
    }

   private:
    void Lock() { pthread_mutex_lock(&lock); }
    void Unlock() { pthread_mutex_unlock(&lock); }
    bool TryLock() { return (pthread_mutex_trylock(&lock) == 0); }
    void WaitWithHokdLock(long timeout_ms) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        long wait_time = ts.tv_nsec + (timeout_ms * 1000000);
        ts.tv_sec += (wait_time / 1000000000);
        ts.tv_nsec = (wait_time % 1000000000);
        pthread_cond_timedwait(&has_item, &lock, &ts);
    }

    void SignalWithHoldLock() { pthread_cond_signal(&has_item); }

    std::queue<T> queue_;
    // 对外公开的锁和条件变量，可用于等待队列非空
    pthread_condattr_t condattr;
    pthread_mutex_t lock;
    pthread_cond_t has_item;
    static const size_t maxSize = 2048;
};

#endif /* THREAD_SAFE_QUEUE_H_ */
