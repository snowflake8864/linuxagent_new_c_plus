#include <time.h>
#include <string.h>
#include <string>
#include "netlog_mgr_db.h"
#include "report_data_control.hpp"
#include "netlog_mgr.h"
#include "common/qh_thread/locker.hpp"
#include "common/utils/file_utils.h"

#define SQLITE3_KEY "osec_sqlite3"
#define TREPORT "osec_log.db"
#define CREATE_T_REPORT_SQL "CREATE TABLE IF NOT EXISTS osec_log (\
ID integer PRIMARY KEY autoincrement,\
content text)"

bool CNetlogMgrDB::InitDB() {
    std::string db_path = "/opt/osec/";
    db_path += TREPORT;

    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);
    bool bResult = true;
    sqlite3 *handle = NULL;
    if (!file_utils::IsFile(db_path)) {
        if (sqlite3_utils::sqlite3CreateDB(db_path.c_str(), &handle) == 0) {
            if (!sqlite3_utils::sqlite3TableExist("osec_log", handle)) {
                bResult &= (sqlite3_utils::sqlite3CreateTable(CREATE_T_REPORT_SQL, handle) == 0);
            }
            sqlite3_utils::sqlite3CloseDB(handle);
        } else {
            bResult = false;
        }
    }
    if (!bResult) {
        LOG_ERROR_DEV("CNetlogMgrDB init db, create report dbfile error or create table error.");
    } else {
        if (sqlite3_utils::sqlite3OpenDBRW(db_path.c_str(), SQLITE3_KEY, &m_handle_) == -1) {
            LOG_ERROR_DEV("CNetlogMgrDB init db, open log index dbfile %s failed", db_path.c_str());
            bResult = false;
        }
    }

    return bResult;
}

bool CNetlogMgrDB::ClearDB() {
    std::string db_path = "/opt/osec/osec_log.db";
    if (!file_utils::IsExist(db_path)) {
        return false;
    }
    QH_THREAD::CMutexManualLocker lck(&m_report_db_locker_);
    lck.lock();
    size_t db_size = file_utils::GetFileSize(db_path);
    if (db_size > 1000 * 1024 * 1024) {
        LOG_INFO("report db need clear, db size is %d bytes", db_size);
        if (m_handle_ != NULL) {
            sqlite3_utils::sqlite3CloseDB(m_handle_);
            m_handle_ = NULL;
        }
        if (file_utils::RemoveFile(db_path)) {
            LOG_INFO("report db remove success");
        }
        lck.unlock();
        InitDB();
        return true;
    }
    lck.unlock();
    return false;
}

bool CNetlogMgrDB::RemoveDataFromDB() {
    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);
    bool bResult = false;
    sqlite3_stmt *stmt = NULL;
    do {
        std::string sql = "delete from osec_log where id in (select id from osec_log limit 200)";
        if (sqlite3_prepare(m_handle_, sql.c_str(), sql.size(), &stmt, NULL) != SQLITE_OK) {
            LOG_ERROR_DEV("CNetlogMgrDB remove data, prepare del from osec_log failed, %s", sqlite3_errmsg(m_handle_));
            break;
        }
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            LOG_ERROR_DEV("CNetlogMgrDB remove DB data, step del from osec_log failed, %s", sqlite3_errmsg(m_handle_));
            break;
        }
        LOG_DEBUG("del from osec_log success");
        bResult = true;
    } while (false);

    if (stmt) sqlite3_finalize(stmt);

    return bResult;
}

bool CNetlogMgrDB::SaveDataToDB(char* lpContent, char* lpUUID) {
    const char* pTmp = "insert into osec_log values(null, ?)";
    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);

    bool bResult = false;
    sqlite3_stmt *stmt = NULL;
    int nInLen = strlen(lpContent);
    do {
        if (sqlite3_prepare(m_handle_, pTmp, strlen(pTmp), &stmt, NULL) != SQLITE_OK) {
            LOG_ERROR_DEV("CNetlogMgrDB save DB data, prepare insert uuid[%s] into osec_log failed, %s", lpUUID, sqlite3_errmsg(m_handle_));
            break;
        }
        sqlite3_bind_text(stmt, 1, lpContent, nInLen, SQLITE_STATIC);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG_ERROR_DEV("CNetlogMgrDB save DB data, step insert id[%s] into osec_log failed, %s", lpUUID, sqlite3_errmsg(m_handle_));
            break;
        }

        LOG_DEBUG("insert id[%s] into osec_log success", lpUUID);
        bResult = true;
    } while (false);

    if (stmt) sqlite3_finalize(stmt);
    return bResult;
}

bool CNetlogMgrDB::ReadData(const int &nSum, std::vector<std::string>& vecData) {
    std::string sql = "SELECT * from osec_log limit 200";
    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);
    bool bResult = false;
    sqlite3_stmt *stmt = NULL;
    std::string str_json = "";
    do {
        if (sqlite3_prepare(m_handle_, sql.c_str(), strlen(sql.c_str()), &stmt, NULL) != SQLITE_OK) {
            //LOG_ERROR_DEV("CNetlogMgrDB load DB fail data, prepare select content from osec_log failed, %s", sqlite3_errmsg(m_handle_));
            LOG_ERROR_DEV("CNetlogMgrDB load DB fail data, prepare select content from osec_log failed!\n");
            break;
        }
        int rc = sqlite3_step(stmt);
        while (rc == SQLITE_ROW) {
            char* content = (char *)sqlite3_column_text(stmt, 1);
            str_json = content;
            vecData.push_back(str_json);
            rc = sqlite3_step(stmt);
        }

        if (rc != SQLITE_DONE) {
            LOG_ERROR_DEV("CNetlogMgrDB load DB fail data, step select content from osec_log failed, %s", sqlite3_errmsg(m_handle_));
            break;
        }
        bResult = true;
        LOG_DEBUG("select content from osec_log success");
    } while (0);

    if (stmt) sqlite3_finalize(stmt);

    return bResult;
}
