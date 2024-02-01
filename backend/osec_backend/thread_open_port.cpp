#include <sstream>
#include "common/log/log.h"
#include "common/uuid.h"
#include "osec_common/socket_osec.h"
#include "backend/osec_backend/kernel_event_handler.h"
#include "thread_open_port.h"

#define DEFAULT_REPORT_SIZE 3

bool CThreadOpenPort::Init() {
    if (m_inited_ == true) {
        LOG_INFO("the CThreadProcess mgr has been inited before.");
        return true;
    }
    m_inited_ = true;
    m_cache_list_.clear();
    QH_THREAD::CMultiThread::SetConcurrentSize(DEFAULT_REPORT_SIZE);
    QH_THREAD::CMultiThread::Run();
    return true;
}

void CThreadOpenPort::UnInit() {
    if (QH_THREAD::CMultiThread::IsRunning()) {
        QH_THREAD::CMultiThread::SynStop();
    }
    QH_THREAD::CMultiThread::Release();
}

void* CThreadOpenPort::thread_function(void* param) {
    std::vector<pOpenPort> vecData;
    while(!QH_THREAD::CMultiThread::IsCancelled()) {
        sleep(5);
        QH_THREAD::CMutexAutoLocker lock(&m_cache_locker_);
        std::list<std::vector<pOpenPort> >::iterator iter;
        for ( iter = m_cache_list_.begin(); iter != m_cache_list_.end(); iter++) {
            vecData = *iter;
            //OSEC_KERNEL_HANDLE->DoTaskUploadOpenPortex(vecData);
            OSEC_KERNEL_HANDLE->AuditOpenPortOper(vecData);
            iter = m_cache_list_.erase(iter);
        }
    }
    return NULL;
}

int CThreadOpenPort::AddOpenPortCache(std::vector<pOpenPort>& infoVec) {
    QH_THREAD::CMutexAutoLocker lock(&m_cache_locker_);
    m_cache_list_.push_back(infoVec);
    return 0;
}
