#ifndef NETMGR_ENTCLIENT_REPORT_DB_HELPER_H_
#define NETMGR_ENTCLIENT_REPORT_DB_HELPER_H_

#include <stdio.h>
#include <string.h>
#include <vector>
#include "common/log/log.h"
#include "common/qh_thread/mutex.hpp"
#include "common/utils/sqlite3_utils.h"

class CNetlogMgrDB
{
  public:
    CNetlogMgrDB() {
        m_handle_ = NULL;
    }
    ~CNetlogMgrDB() {
        if (m_handle_ != NULL) {
            sqlite3_utils::sqlite3CloseDB(m_handle_);
            m_handle_ = NULL;
        }
    }

  public:
    bool InitDB();
    bool ClearDB();
    bool RemoveDataFromDB(char * lpUUID);
    bool SaveDataToDB(char *lpContent, char* lpUUID);
    bool ReadData(const int &nSum, std::vector<std::string>& vecData);
    bool RemoveDataFromDB();
    static CNetlogMgrDB* GetInstance() {
        static CNetlogMgrDB db;
        return &db;
    }

  private:
    QH_THREAD::CMutex m_report_db_locker_;
    sqlite3* m_handle_;
};

#define CNETLOGMGRDB (CNetlogMgrDB::GetInstance())

#endif /* NETMGR_ENTCLIENT_REPORT_DB_HELPER_H_ */
