#include "timer/timer.h"
#include "utils/proc_info_utils.h"

CTaskWorker::CTaskWorker(int size) {
    QH_THREAD::CMultiThread::SetConcurrentSize(size);
    QH_THREAD::CMultiThread::Run();
}

CTaskWorker::~CTaskWorker() {
    if (QH_THREAD::CMultiThread::IsRunning()) {
        QH_THREAD::CMultiThread::SynStop();
    }
    QH_THREAD::CMultiThread::Release();
}

void CTaskWorker::AddTask(TimerHandler taskinfo) {
    QH_THREAD::CMutexAutoLocker Lck(&m_queue_mutex_);
    m_task_queue_.push(taskinfo);
}

void *CTaskWorker::thread_function(void *param) {
    LOG_DEBUG("timer task worker thread[%d] started.", proc_info_utils::GetTid());
    while(!QH_THREAD::CMultiThread::IsCancelled()) {
        TimerHandler taskinfo = NULL;
        {
            QH_THREAD::CMutexManualLocker Lck(&m_queue_mutex_);
            Lck.lock();
            if (m_task_queue_.size() > 0) {
                taskinfo = m_task_queue_.front();
                m_task_queue_.pop();
                Lck.unlock();
            } else {
                Lck.unlock();
                usleep(100 * 1000);
            }
        }
        if (NULL != taskinfo) {
            taskinfo();
        }
    }
    LOG_DEBUG("timer task worker thread[%d] exit.", proc_info_utils::GetTid());
    return NULL;
}

CTimer::CTimer()
    : m_lRefCount_CTimer(0)
    , m_click_time_(1) {
    p_task_worker_ = new (std::nothrow) CTaskWorker(DEFAULT_TASK_WORKER_SIZE);
    if (p_task_worker_ == NULL) {
        LOG_ERROR("create timer task worker failed, out of memory.");
    } else {
        p_task_worker_->Run();
    }
    QH_THREAD::CThread::run(NULL);
}

CTimer::~CTimer() {
    QH_THREAD::CThread::quit();
    QH_THREAD::CThread::join();
    if (NULL != p_task_worker_) {
        delete p_task_worker_;
        p_task_worker_ = NULL;
    }
}

int CTimer::RegisterEvent(TimerHandlerConf stConf, const std::string &strTimerName) {
    QH_THREAD::CMutexAutoLocker lock(&m_muxlck_);
    if (stConf.cycle_time < m_click_time_ || stConf.handler == NULL)
        return -1;

    if (m_eventsmap_.find(strTimerName) != m_eventsmap_.end())
        return -1;

    m_eventsmap_.insert(std::make_pair(strTimerName, stConf));
    return 0;
}

int CTimer::UnRegisterEvent(const std::string &strTimerName) {
    QH_THREAD::CMutexAutoLocker lock(&m_muxlck_);
    std::map<std::string, TimerHandlerConf>::iterator it;
    it = m_eventsmap_.find(strTimerName);
    if (it == m_eventsmap_.end())
        return -1;

    m_eventsmap_.erase(it);
    return 0;
}

int CTimer::RefreshTimer(TimerHandlerConf stConf, const std::string strTimerName) {
	QH_THREAD::CMutexAutoLocker lock(&m_muxlck_);
    if (stConf.cycle_time < m_click_time_ || stConf.handler == NULL)
        return -1;

    if (m_eventsmap_.find(strTimerName) == m_eventsmap_.end())
        return -1;

    m_eventsmap_[strTimerName] = stConf;
    return 0;
}
void CTimer::TimerLoop() {
    while(1) {
        if (doWaitOrQuit(m_click_time_)) {
            break;
        }
        QH_THREAD::CMutexAutoLocker lock(&m_muxlck_);
        std::map<std::string, TimerHandlerConf>::iterator it;
        it = m_eventsmap_.begin();
        for (; it != m_eventsmap_.end(); ++it) {
            it->second.start_time -= m_click_time_;
            if (it->second.start_time <= 0) {
                if (it->second.repeat_count > 0 || it->second.repeat_count == -1) {
                    if (it->second.handler != NULL && p_task_worker_ != NULL) {
                        p_task_worker_->AddTask(it->second.handler);
                    }
                    if (it->second.repeat_count > 0) {
                        --(it->second.repeat_count);
                    }
                    it->second.start_time = it->second.cycle_time;
                }
            }
        }
    }
}
