#include "cpu_limit/cpu_limit_mgr.h"
#include "cpu_limit/include/cpu_limit.h"
#include "log/log.h"

bool CpuLimitManager::Init() {
    pthread_mutex_init(&m_lock, NULL);
    m_threadset.clear();
    m_speed = 100;
    m_init = true;
    return true;
}

void CpuLimitManager::SyncStop() {
    if (!m_init)
        return;

    pthread_mutex_destroy(&m_lock);
    m_threadset.clear();
    m_speed = 100;
    Singleton<CPULimit>::Uninit();
}

void CpuLimitManager::SpeedCtrl() {
    if (!m_init)
        return;
    Singleton<CPULimit>::Instance().monitor();
}

void CpuLimitManager::SetCpuLimitMode(int mode) {
    if (!m_init)
        return;

    if (mode < 0 || mode > 2) {
        LOG_ERROR("set cpu limit mode failed: unsupport mode %d", mode);
        return;
    }

    unsigned int speed = 25 * mode;
    if (mode == 0) speed = 100;
    if (speed == m_speed) {
        LOG_INFO("set cpu limit mode, but unchanged speed %d ", speed);
        return;
    }

    std::set<pthread_t> threadset_failed;
    std::set<pthread_t> threadset_copy;
    std::set<pthread_t>::iterator it;
    //缩小锁范围，进行拷贝
    if (!m_threadset.empty()) {
        pthread_mutex_lock(&m_lock);
        threadset_copy.insert(m_threadset.begin(), m_threadset.end());
        pthread_mutex_unlock(&m_lock);

        //遍历进行绑定
        it = threadset_copy.begin();
        for (; it != threadset_copy.end(); ++it) {
            if (Singleton<CPULimit>::Instance().setSpeed(speed, *it) != 0) {
                threadset_failed.insert(*it);
            } else {
                m_speed = speed;
            }
        }
    }

    //移除 由于线程不存在，导致的绑定失败的 线程
    if (!threadset_failed.empty()) {
        it = threadset_failed.begin();
        for (; it != threadset_failed.end(); ++it) {
            DeleteThread(*it);
        }
    }
}

void CpuLimitManager::AddThread(pthread_t thread) {
    if (!m_init)
        return;

    //线程不存在，导致绑定失败， 线程不加入队列中
    if (Singleton<CPULimit>::Instance().setSpeed(m_speed, thread) == 0) {
        LOG_DEBUG("add thread to cpulimit manager success");
        pthread_mutex_lock(&m_lock);
        m_threadset.insert(thread);
        pthread_mutex_unlock(&m_lock);
    } else {
        LOG_ERROR("add thread to cpulimit manager failed");
    }
}

void CpuLimitManager::DeleteThread(pthread_t thread) {
    if (!m_init)
        return;

    LOG_DEBUG("delete thread from cpulimit manager");

    if (!m_threadset.empty()) {
        pthread_mutex_lock(&m_lock);
        std::set<pthread_t>::iterator it;
        it = m_threadset.find(thread);
        if (it != m_threadset.end())
            m_threadset.erase(it);
        pthread_mutex_unlock(&m_lock);
    }
}
