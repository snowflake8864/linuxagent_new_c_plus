#include "multi_thread.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <vector>
#include "log/log.h"

QH_THREAD::CMultiThread::CMultiThread()
    : concurrent_size_(1)
    , pthread_array_(NULL) {
}

bool QH_THREAD::CMultiThread::Run() {
    if (IsRunning()) {
        return true;
    }
    // 清除已经结束但没有join的线程
    SynStop();

    pause_quit_helper_.Lock();
    pause_quit_helper_.Reset(QH_THREAD::CPauseQuitHelper::NO_NEED_LOCK);
    if (pthread_array_ == NULL) {
        pthread_array_ = (pthread_t *) new (std::nothrow) pthread_t[concurrent_size_];
        memset(pthread_array_, 0, sizeof(pthread_t) * concurrent_size_);
    }
    if (pthread_array_ == NULL) {
        LOG_ERROR("create thread failed: out of memory");
        pause_quit_helper_.Unlock();
        return false;
    }
    int cur_thread_cnt = 0;
    for (; cur_thread_cnt < concurrent_size_; ++cur_thread_cnt) {
        int ret = pthread_create(&(pthread_array_[cur_thread_cnt]), NULL,
                                 &private_thread_func, this);
        if (ret != 0) {
            LOG_ERROR("create thread failed, return code : %d", ret);
            break;
        }
        AddCpuLimit(pthread_array_[cur_thread_cnt]);
    }
    if (cur_thread_cnt != concurrent_size_) {
        //线程创建发生失败，需要取消已运行线程
        pause_quit_helper_.Unlock();
        pause_quit_helper_.Quit();
        SynStopByCount(cur_thread_cnt);
        return false;
    }
    pause_quit_helper_.Unlock();
    return true;
}

void QH_THREAD::CMultiThread::AsynStop() { pause_quit_helper_.Quit(); }

void QH_THREAD::CMultiThread::SynStopByCount(int thread_count) {
    AsynStop();

    QH_THREAD::CMutexAutoLocker _locker(&lock_);
    if (pthread_array_ == NULL) {
        return;
    }

    // try join, wait for all thread exit
    std::vector<pthread_t> ptherad_vector;
    for (int i = 0; i < thread_count; ++i)
        ptherad_vector.push_back(pthread_array_[i]);

    delete[] pthread_array_;
    pthread_array_ = NULL;

    while (ptherad_vector.size() != 0) {
        std::vector<pthread_t>::iterator it = ptherad_vector.begin();
        while (it != ptherad_vector.end()) {
            int ret = pthread_tryjoin_np(*it, NULL);
            switch (ret) {
            case 0: //正常结束
                RemoveCpuLimit(*it);
                it = ptherad_vector.erase(it);
                break;
            case ESRCH: //进程未启动或已经结束被join过
                it = ptherad_vector.erase(it);
                break;
            case EINVAL:
                it = ptherad_vector.erase(it);
                break;
            default:
                ++it;
                break;
            }
            usleep(100);
        }
    }
}

void QH_THREAD::CMultiThread::SynStop() { SynStopByCount(concurrent_size_); }

void QH_THREAD::CMultiThread::SetConcurrentSize(int size) {
    QH_THREAD::CMutexAutoLocker _locker(&lock_);
    concurrent_size_ = size;
}

int QH_THREAD::CMultiThread::GetConcurrentSize() {
    QH_THREAD::CMutexAutoLocker _locker(&lock_);
    return concurrent_size_;
}

bool QH_THREAD::CMultiThread::IsCancelled() { return pause_quit_helper_.IsQuit(); }

bool QH_THREAD::CMultiThread::IsRunning() {
    QH_THREAD::CMutexAutoLocker _locker(&lock_);
    if (pthread_array_ == NULL) {
        return false;
    }
    bool is_running = false;
    for (int i = 0; i < concurrent_size_; ++i) {
        if (pthread_kill(pthread_array_[i], 0) == 0) {
            is_running = true;
            break;
        }
    }
    return is_running;
}

long QH_THREAD::CMultiThread::Release() {
    SynStop();
    return 0;
}

void QH_THREAD::CMultiThread::GetThreadId(pthread_t **thread, int *size) {
    QH_THREAD::CMutexAutoLocker _locker(&lock_);
    *thread = pthread_array_;
    *size = concurrent_size_;
}

void *QH_THREAD::CMultiThread::private_thread_func(void *this_ptr) {
    if (!this_ptr) return NULL;

    QH_THREAD::CMultiThread *cur_thread = (QH_THREAD::CMultiThread *)this_ptr;
    return cur_thread->thread_function(NULL);
}

bool QH_THREAD::CMultiThread::IsPause() { return pause_quit_helper_.IsPause(); }

void QH_THREAD::CMultiThread::Pause() { pause_quit_helper_.Pause(); }

void QH_THREAD::CMultiThread::Resume() { pause_quit_helper_.Resume(); }

bool QH_THREAD::CMultiThread::DoPauseOrQuit() { return pause_quit_helper_.DoPauseOrQuit(); }
