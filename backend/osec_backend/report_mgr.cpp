#include "report_mgr.h"
#include <sstream>
#include "common/log/log.h"
#include "common/uuid.h"
#include "osec_common/socket_osec.h"
#include "backend/net_agent/ent_client_net_agent.h"

#define DEFAULT_REPORT_SIZE 3

bool CNetReportMgr::Init(CEntClientNetAgent *pSocket) {
    if (m_inited_ == true) {
        LOG_INFO("the report mgr has been inited before.");
        return true;
    }
    m_pSock = pSocket;
    m_inited_ = true;
    m_reportdata_list_.clear();
    QH_THREAD::CMultiThread::SetConcurrentSize(DEFAULT_REPORT_SIZE);
    QH_THREAD::CMultiThread::Run();
    return true;
}

void CNetReportMgr::UnInit() {
    if (QH_THREAD::CMultiThread::IsRunning()) {
        QH_THREAD::CMultiThread::SynStop();
    }
    QH_THREAD::CMultiThread::Release();
}

std::string CNetReportMgr::CreateReportMsgUUID() {
    char messgae_uuid[UUID_LEN];
    memset(messgae_uuid, 0, UUID_LEN);
    while (uuid::UUID_ESUCCESS != uuid::uuid4_generate(messgae_uuid)) {
        LOG_ERROR_DEV("CNetReportMgr report msg UUID create, create uuid failed.");
        usleep(100 * 1000);
        continue;
    }
    return std::string(messgae_uuid);
}

int CNetReportMgr::Report(const LOG_INFO& loginfo) {
    // 未初始化时不进行上报，如单机版本、控制中心IP或PORT为空等非法情况
    if (false == m_inited_) {
        return 0;
    }

    int hRtn = -1;
    do {

        {
            QH_THREAD::CMutexAutoLocker lck(&m_reportdata_locker_);
            m_reportdata_list_.push_back(loginfo);
        }

        hRtn = 0;
    } while(false);
    return hRtn;
}

void* CNetReportMgr::thread_function(void* param) {
    //LOG_INFO("Thread [%ld], syn report thread start!", (long) proc_info_utils::GetTid());

    while(!QH_THREAD::CMultiThread::IsCancelled()) {
        ReportSynData();
    }
    //LOG_INFO("Thread [%ld], syn report thread exit!", (long) proc_info_utils::GetTid());

    return NULL;
}

#include "osec_common/osec_socket_utils.h"
#include "osec_common/socket_osec.h"
#include "common/md5sum.h"
#include "backend/net_agent/data_operation/build_json.h"
void CNetReportMgr::ReportSynData() {
    while (1) {
        LOG_INFO loginfo;
        int flag = 0;
        {
            QH_THREAD::CMutexManualLocker lck(&m_reportdata_locker_);
            lck.lock();
            if (!m_reportdata_list_.empty()) {
                loginfo = m_reportdata_list_.front();
                m_reportdata_list_.pop_front();
                flag = 1;
                lck.unlock();
            } else {
                lck.unlock();
                usleep(100 * 1000);
                flag = 0;
                break;
            }
        }
        if (flag) {
            LOG_DEBUG("upload file log name:%s, type :%d.....", loginfo.file_path.c_str(), loginfo.nType);
            std::vector<LOG_INFO> loginfo_vec;
            std::string str_json;
            if (loginfo.md5.empty()) {
                loginfo.md5 = md5sum::md5file(loginfo.file_path.c_str());
            }
            loginfo_vec.push_back(loginfo);
            build_json::BuildAlertLogJson(loginfo_vec, str_json);
            m_pSock->DoUploadClientLog(str_json);
        }

        //REPORTDBHELPERPTR->RemoveDataFromDB(lpUUID);
    }
}
