#ifndef QH_THREAD_LOCKER_HPP_
#define QH_THREAD_LOCKER_HPP_

#include "qh_thread/mutex.hpp"
#include "qh_thread/cond.hpp"
#include "qh_thread/rwlock.hpp"
#include "qh_thread/filelock.hpp"

namespace QH_THREAD {
class CMutexAutoLocker {
  public:
    CMutexAutoLocker(CMutex * cmutex)
        : m_error_num_ (0)
        , p_cmutex_(cmutex) {
        if (p_cmutex_) {
            m_error_num_ = pthread_mutex_lock(p_cmutex_->get_mutex());
        }
    }

    ~CMutexAutoLocker() {
        if (p_cmutex_) {
            m_error_num_ = pthread_mutex_unlock(p_cmutex_->get_mutex());
        }
    }
  public:
    int get_error() {
        return m_error_num_;
    }
  private:
    int m_error_num_;
    CMutex *p_cmutex_;
}; // CMutexAutoLocker

class CMutexManualLocker {
  public:
    CMutexManualLocker(CMutex * cmutex):
        p_cmutex_(cmutex) {
    }
  public:
    int lock() {
        if (p_cmutex_) {
            return pthread_mutex_lock(p_cmutex_->get_mutex());
        }
        return 0;
    }

    int unlock() {
        if (p_cmutex_) {
            return pthread_mutex_unlock(p_cmutex_->get_mutex());
        }
        return 0;
    }
  private:
    CMutex * p_cmutex_;
}; // CMutexManualLocker

class CWriteAutoLocker {
  public:
    CWriteAutoLocker(CRwlock * crwlock)
        : m_error_num_ (0)
        , p_crwlock_(crwlock) {
        if (p_crwlock_) {
            m_error_num_ = pthread_rwlock_wrlock(p_crwlock_->get_lock());
        }
    }
    ~CWriteAutoLocker() {
        if (p_crwlock_) {
            pthread_rwlock_unlock(p_crwlock_->get_lock());
        }
    }
  public:
    int get_error() { return m_error_num_; }

  private:
    int m_error_num_;
    CRwlock * p_crwlock_;
}; //CWriteAutoLocker

class CWriteManualLocker {
  public:
    CWriteManualLocker(CRwlock * crwlock):
        p_crwlock_(crwlock) {
    }
  public:
    int lock() {
        if (p_crwlock_) {
            return pthread_rwlock_wrlock(p_crwlock_->get_lock());
        }
        return 0;
    }

    int unlock() {
        if (p_crwlock_) {
            return pthread_rwlock_unlock(p_crwlock_->get_lock());
        }
        return 0;
    }
  private:
    CRwlock * p_crwlock_;
}; // CWriteManualLocker

class CReadAutoLocker {
  public:
    CReadAutoLocker(CRwlock * crwlock)
        : m_error_num_ (0)
        , p_crwlock_(crwlock) {
        if (p_crwlock_) {
            m_error_num_ = pthread_rwlock_rdlock(p_crwlock_->get_lock());
        }
    }

    ~CReadAutoLocker() {
        if (p_crwlock_) {
            pthread_rwlock_unlock(p_crwlock_->get_lock());
        }
    }
  public:
    int get_error() { return m_error_num_; }
  private:
    int m_error_num_;
    CRwlock * p_crwlock_;
}; // CReadAutoLocker

class CReadManualLocker {
  public:
    CReadManualLocker(CRwlock * crwlock):
        p_crwlock_(crwlock) {
    }
  public:
    int lock()
    {
        if (p_crwlock_) {
            return pthread_rwlock_rdlock(p_crwlock_->get_lock());
        }
        return 0;
    }

    int unlock()
    {
        if (p_crwlock_) {
            return pthread_rwlock_unlock(p_crwlock_->get_lock());
        }
        return 0;
    }
  private :
    CRwlock * p_crwlock_;
}; // CReadManualLocker

class CFileLockAutoLocker {
  public:
    CFileLockAutoLocker(CFileLock* cfilelock)
        : m_error_num_ (0)
        , p_cfilelock_(cfilelock) {
        if (p_cfilelock_) {
            m_error_num_ = p_cfilelock_->lock();
        }
    }

    ~CFileLockAutoLocker()
    {
        if (p_cfilelock_) {
            m_error_num_ = p_cfilelock_->unlock();
        }
    }
    int get_error() { return m_error_num_; }
  private:
    int m_error_num_;
    CFileLock* p_cfilelock_;
}; // CFileLockAutoLocker
} // namespace

#endif /* QH_THREAD_LOCKER_HPP_ */