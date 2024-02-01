#ifndef NETMGR_ENTCLIENT_REPORT_DB1_HELPER_H_
#define NETMGR_ENTCLIENT_REPORT_DB1_HELPER_H_

#include <stdio.h>
#include <string.h>
#include "common/log/log.h"
#include "common/qh_thread/mutex.hpp"
#include "common/utils/sqlite3_utils.h"
#include "osec_common/global_config.hpp"
#include "osec_common/global_message.h"

class CReportDBHelper
{
  public:
    CReportDBHelper() {
        m_handle_ = NULL;
    }
    ~CReportDBHelper() {
        if (m_handle_ != NULL) {
            sqlite3_utils::sqlite3CloseDB(m_handle_);
            m_handle_ = NULL;
        }
    }

  public:
    bool InitDB();
    bool RemoveDataFromDB(char * lpUUID);
    bool SaveDataToDB(const LOG_INFO& loginfo, char* lpUUID);
    bool LoadFailData(LOG_INFO& loginfo);

    static CReportDBHelper* GetInstance() {
        static CReportDBHelper db;
        return &db;
    }

  private:
    QH_THREAD::CMutex m_report_db_locker_;
    sqlite3* m_handle_;
};

#define REPORTDBHELPERPTR (CReportDBHelper::GetInstance())

#endif /* NETMGR_ENTCLIENT_REPORT_DB_HELPER_H_ */
