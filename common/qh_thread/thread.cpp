#include "qh_thread/thread.h"
#include <errno.h>
#include <strings.h>
#include <signal.h>

void QH_THREAD::CPauseQuitHelper::Reset(LOCK_TYPE lock_type) {
    if (lock_type == NEED_LOCK) {
        CMutexAutoLocker locker(&m_mutex_);
        m_is_pause_ = false;
        m_is_quit_ = false;
    } else {
        m_is_pause_ = false;
        m_is_quit_ = false;
    }
}

QH_THREAD::CPauseQuitHelper::CPauseQuitHelper()
    : m_is_quit_(true)
    , m_is_pause_(false) {
    m_cond_.Init(&m_mutex_);
}

void QH_THREAD::CPauseQuitHelper::Pause() {
    CMutexAutoLocker locker(&m_mutex_);
    m_is_pause_ = true;
}

void QH_THREAD::CPauseQuitHelper::Resume() {
    CMutexAutoLocker locker(&m_mutex_);
    m_is_pause_ = false;
    m_cond_.BroadCast();
}

void QH_THREAD::CPauseQuitHelper::Quit() {
    CMutexAutoLocker locker(&m_mutex_);
    m_is_quit_ = true;
    m_cond_.BroadCast();
}

void QH_THREAD::CPauseQuitHelper::Signal() {
    CMutexAutoLocker locker(&m_mutex_);
    m_cond_.Signal();
}

bool QH_THREAD::CPauseQuitHelper::IsQuit() {
    CMutexAutoLocker locker(&m_mutex_);
    return m_is_quit_;
}

bool QH_THREAD::CPauseQuitHelper::IsPause() {
    CMutexAutoLocker locker(&m_mutex_);
    return m_is_pause_;
}

bool QH_THREAD::CPauseQuitHelper::DoPauseOrQuit() {
    if (m_is_quit_) {
        return true;
    }
    if (m_is_pause_) {
        CMutexManualLocker locker(&m_mutex_);
        locker.lock();
        while (!m_is_quit_ && m_is_pause_) {
            m_cond_.Wait();
        }
        locker.unlock();
        return IsQuit();
    } else {
        return false;
    }
}

bool QH_THREAD::CPauseQuitHelper::DoWaitOrQuit(int second) {
    if (m_is_quit_) {
        return true;
    }

    CMutexManualLocker locker(&m_mutex_);
    locker.lock();
    if (!m_is_quit_) {
        if(second < 0){
            m_cond_.Wait();
        }else{
            m_cond_.WaitTimeoutSecond(second);
        }
    }
    locker.unlock();
    return IsQuit();
}

void QH_THREAD::CPauseQuitHelper::Lock() {
    CMutexManualLocker locker(&m_mutex_);
    locker.lock();
}

void QH_THREAD::CPauseQuitHelper::Unlock() {
    CMutexManualLocker locker(&m_mutex_);
    locker.unlock();
}

QH_THREAD::PauseQuitHelperAutoLocker QH_THREAD::CPauseQuitHelper::GetAutoLocker() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        new QH_THREAD::CMutexAutoLocker(&m_mutex_));
    return locker;
}

int QH_THREAD::CThread::run(void *param) {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    m_pause_quit_helper_.Reset(CPauseQuitHelper::NO_NEED_LOCK);
    p_param_ = param;
    int ret = pthread_create(&m_hthread_, NULL, &private_thread_func, this);
    if (ret == 0) {
        m_valid_thread_id_ = true;
    } else {
        m_valid_thread_id_ = false;
    }
    return ret;
}

void *QH_THREAD::CThread::get_param() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    return p_param_;
}

int QH_THREAD::CThread::detach() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_valid_thread_id_) {
        return pthread_detach(m_hthread_);
    }
    return ESRCH;
}

bool QH_THREAD::CThread::isRunning() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_valid_thread_id_) {
        return 0 == pthread_kill(m_hthread_, 0);
    }
    return false;
}

void QH_THREAD::CThread::quit() { m_pause_quit_helper_.Quit(); }

void QH_THREAD::CThread::pause() { m_pause_quit_helper_.Pause(); }

void QH_THREAD::CThread::resume() { m_pause_quit_helper_.Resume(); }

void QH_THREAD::CThread::signal() { m_pause_quit_helper_.Signal(); }

bool QH_THREAD::CThread::isQuit() { return m_pause_quit_helper_.IsQuit(); }

bool QH_THREAD::CThread::isPause() {
    return m_pause_quit_helper_.IsPause();
}

void *QH_THREAD::CThread::private_thread_func(void *this_ptr) {
    CThread *cur_thread = (CThread *) this_ptr;
    if (!cur_thread) return NULL;
    cur_thread->PreAction();
    cur_thread->thread_function(cur_thread->get_param());
    cur_thread->PostAction();
    return NULL;
}

int QH_THREAD::CThread::join() {
    void *pret = NULL;
    m_pause_quit_helper_.Lock();
    if (m_valid_thread_id_) {
        m_pause_quit_helper_.Unlock();
        return pthread_join(m_hthread_, &pret);
    }
    m_pause_quit_helper_.Unlock();
    return 0;
}

int QH_THREAD::CThread::tryjoin_np() {
    void *pret = NULL;
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_valid_thread_id_) {
        return pthread_tryjoin_np(m_hthread_, &pret);
    }
    return 0;
}

bool QH_THREAD::CThread::isRealQuit() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_valid_thread_id_) {
        return ESRCH == pthread_kill(m_hthread_, 0);
    }
    return true;
}

bool QH_THREAD::CThread::doPauseOrQuit() {
    return m_pause_quit_helper_.DoPauseOrQuit();
}

bool QH_THREAD::CThread::doWaitOrQuit(int second) {
    return m_pause_quit_helper_.DoWaitOrQuit(second);
}

QH_THREAD::CThread::CThread() {
    bzero(&m_hthread_, sizeof(m_hthread_));
    p_param_ = NULL;
    m_valid_thread_id_ = false;
}

int QH_THREAD::CWorkerThread::Run(void *param) {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    m_pause_quit_helper_.Reset(CPauseQuitHelper::NO_NEED_LOCK);
    m_param_ = param;
    int ret = pthread_create(&m_thread_handle_, NULL, &PrivateThreadFunc, this);
    if (ret == 0) {
        m_is_valid_thread_id_ = true;
    } else {
        m_is_valid_thread_id_ = false;
    }
    return ret;
}

void *QH_THREAD::CWorkerThread::GetParam() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    return m_param_;
}

int QH_THREAD::CWorkerThread::Detach() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_is_valid_thread_id_) {
        return pthread_detach(m_thread_handle_);
    }
    return ESRCH;
}

bool QH_THREAD::CWorkerThread::IsRunning() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_is_valid_thread_id_) {
        return 0 == pthread_kill(m_thread_handle_, 0);
    }
    return false;
}

void QH_THREAD::CWorkerThread::Quit() { m_pause_quit_helper_.Quit(); }

void QH_THREAD::CWorkerThread::Pause() { m_pause_quit_helper_.Pause(); }

void QH_THREAD::CWorkerThread::Resume() { m_pause_quit_helper_.Resume(); }

bool QH_THREAD::CWorkerThread::IsQuit() { return m_pause_quit_helper_.IsQuit(); }

bool QH_THREAD::CWorkerThread::IsPause() { return m_pause_quit_helper_.IsPause(); }

void *QH_THREAD::CWorkerThread::PrivateThreadFunc(void *this_ptr) {
    CWorkerThread *cur_thread = (CWorkerThread *)this_ptr;
    cur_thread->PreAction();
    void *ret = cur_thread->p_thread_fun_(cur_thread->m_param_);
    cur_thread->PostAction();
    return ret;
}

int QH_THREAD::CWorkerThread::Join() {
    void *pret = NULL;
    m_pause_quit_helper_.Lock();
    if (m_is_valid_thread_id_) {
        m_pause_quit_helper_.Unlock();
        return pthread_join(m_thread_handle_, &pret);
    }
    m_pause_quit_helper_.Unlock();
    return 0;
}

int QH_THREAD::CWorkerThread::TryjoinNp() {
    void *pret = NULL;
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_is_valid_thread_id_) {
        return pthread_tryjoin_np(m_thread_handle_, &pret);
    }
    return 0;
}

bool QH_THREAD::CWorkerThread::IsRealQuit() {
    QH_THREAD::PauseQuitHelperAutoLocker locker(
        m_pause_quit_helper_.GetAutoLocker());
    if (m_is_valid_thread_id_) {
        return ESRCH == pthread_kill(m_thread_handle_, 0);
    }
    return true;
}

bool QH_THREAD::CWorkerThread::DoPauseOrQuit() {
    return m_pause_quit_helper_.DoPauseOrQuit();
}

bool QH_THREAD::CWorkerThread::DoWaitOrQuit(int second) {
    return m_pause_quit_helper_.DoWaitOrQuit(second);
}

QH_THREAD::CWorkerThread::CWorkerThread() {
    bzero(&m_thread_handle_, sizeof(m_thread_handle_));
    m_param_ = NULL;
    m_is_valid_thread_id_ = false;
}
