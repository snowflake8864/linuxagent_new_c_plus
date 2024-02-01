#include "netlog_mgr.h"
#include "netlog_mgr_db.h"
#include <sstream>
#include "common/utils/proc_info_utils.h"
#include "common/log/log.h"
#include "common/uuid.h"
#include "common/utils/net_utils.h"
#include "common/utils/file_utils.h"
#include "net_agent/data_operation/build_json.h"
#include "backend/net_agent/ent_client_net_agent.h"

#define DEFAULT_REPORT_SIZE 1

bool CNetlogMgr::Init() {
    if (m_inited_ == true) {
        LOG_INFO("the report mgr has been inited before.");
        return true;
    }
    m_pAgentClient = NULL;
    m_inited_ = true;
    CNETLOGMGRDB->ClearDB();
    CNETLOGMGRDB->InitDB();
    QH_THREAD::CMultiThread::SetConcurrentSize(DEFAULT_REPORT_SIZE);
    QH_THREAD::CMultiThread::Run();
    return true;
}

void CNetlogMgr::UnInit() {
    if (QH_THREAD::CMultiThread::IsRunning()) {
        QH_THREAD::CMultiThread::SynStop();
    }
    QH_THREAD::CMultiThread::Release();
}

void CNetlogMgr::SetAgentClient(CEntClientNetAgent *Agent) {
    if (Agent) {
        m_pAgentClient = Agent;
    }
}

std::string CNetlogMgr::CreateReportMsgUUID() {
    char messgae_uuid[UUID_LEN];
    memset(messgae_uuid, 0, UUID_LEN);
    while (uuid::UUID_ESUCCESS != uuid::uuid4_generate(messgae_uuid)) {
        LOG_ERROR_DEV("CNetlogMgr report msg UUID create, create uuid failed.");
        usleep(100 * 1000);
        continue;
    }
    return std::string(messgae_uuid);
}

void* CNetlogMgr::thread_function(void* param) {
    LOG_INFO("Thread [%ld], syn report thread start!", (long) proc_info_utils::GetTid());

    while(!QH_THREAD::CMultiThread::IsCancelled()) {
        if (m_pAgentClient->m_bOnlineClient) {
            SynReport();
            sleep(60*5);
        } else {
            sleep(60);
        }

    }

    LOG_INFO("Thread [%ld], syn report thread exit!", (long) proc_info_utils::GetTid());
    return NULL;
}

bool CNetlogMgr::SynReport() {

    std::string str_json;
    std::vector<std::string> vecData;
    bool bFirstFlag = false;
    QH_THREAD::CMutexAutoLocker lck(&m_netlog_locker_);
    int nSum = 200;
    while (true) {
        vecData.clear();
        str_json = "";
        CNETLOGMGRDB->ReadData(nSum, vecData);
        if (vecData.size()<=0) {
            //LOG_INFO("data count size:%d, break", vecData.size());
            break;
        }

        //LOG_INFO("data count size:%d", vecData.size());
        if ( (true == bFirstFlag) && (vecData.size()<100)) {
             LOG_INFO("not bFirstFlag data count size:%d, break", vecData.size());
            break;
        }
        build_json::BuildJsonByString(vecData, str_json);
        if (m_pAgentClient) {
            m_pAgentClient->DoUploadHttpSyslog(str_json);
            //LOG_INFO("report succes content[%s]", str_json.c_str());
            CNETLOGMGRDB->RemoveDataFromDB();
            bFirstFlag = true;
        }
    }
    return true;
}

bool CNetlogMgr::SaveData(std::string str_data) {
    std::string str_uuid = "1234a";
    QH_THREAD::CMutexAutoLocker lck(&m_netlog_locker_);
    CNETLOGMGRDB->SaveDataToDB((char*)str_data.c_str(), (char*)str_uuid.c_str());
    //LOG_INFO("save db:%s", str_data.c_str());
    LOG_DEBUG("save db:%s", str_data.c_str());
    return true;
}
