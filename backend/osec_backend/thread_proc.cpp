#include <sstream>
#include "common/log/log.h"
#include "common/uuid.h"
#include "osec_common/socket_osec.h"
#include "backend/osec_backend/kernel_event_handler.h"
#include "thread_proc.h"

#define DEFAULT_REPORT_SIZE 3

bool CThreadProcess::Init() {
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

void CThreadProcess::UnInit() {
    if (QH_THREAD::CMultiThread::IsRunning()) {
        QH_THREAD::CMultiThread::SynStop();
    }
    QH_THREAD::CMultiThread::Release();
}

void* CThreadProcess::thread_function(void* param) {
    std::string file_hash;
    int level = 0;
    std::string edr_pram;
    std::string edr_ppram;
    struct av_process_info procinfo;
    while(!QH_THREAD::CMultiThread::IsCancelled()) {
        sleep(5);
        QH_THREAD::CMutexAutoLocker lock(&m_cache_locker_);
        std::list<struct av_process_info>::iterator iter;
        for ( iter = m_cache_list_.begin(); iter != m_cache_list_.end(); iter++) {
            procinfo = *iter;
            OSEC_KERNEL_HANDLE->Process_match_handle(procinfo, file_hash, level); //是不是重复了
            OSEC_KERNEL_HANDLE->AuditProcessOper(&procinfo, file_hash, level, edr_pram, edr_ppram);
            iter = m_cache_list_.erase(iter);
        }
    }
    return NULL;
}

int CThreadProcess::AddProcessCache(struct av_process_info& info) {
    QH_THREAD::CMutexAutoLocker lock(&m_cache_locker_);
    m_cache_list_.push_back(info);
    return 0;
}
