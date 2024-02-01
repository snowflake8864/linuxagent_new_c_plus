#include <time.h>
#include <string.h>
#include <string>
#include "report_db_helper.h"
#include "report_mgr.h"
#include "common/qh_thread/locker.hpp"
#include "common/utils/file_utils.h"

#define SQLITE3_KEY "osecforlinux_sqlite3"
#define TREPORT "t_report.db"
#define CREATE_T_REPORT_SQL "CREATE TABLE IF NOT EXISTS t_report (\
uuid text NOT NULL UNIQUE PRIMARY KEY,\
file_path text,\
md5 text,\
nType int,\
nLevel int,\
nTime int,\
rename_dir text,\
notice_remark text,\
exception_process text)"

bool CReportDBHelper::InitDB() {

    std::string db_path = "/opt/osec/";
    if(!file_utils::IsExist(db_path)) {
        file_utils::MakeDirs(db_path, 0755);
    }
    db_path += TREPORT;

    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);
    bool bResult = true;
    sqlite3 *handle = NULL;
    if (!file_utils::IsFile(db_path)) {
        if (sqlite3_utils::sqlite3CreateDB(db_path.c_str(), &handle) == 0) {
            if (!sqlite3_utils::sqlite3TableExist("t_report", handle)) {
                bResult &= (sqlite3_utils::sqlite3CreateTable(CREATE_T_REPORT_SQL, handle) == 0);
            }
            sqlite3_utils::sqlite3CloseDB(handle);
        } else {
            bResult = false;
        }
    }
    if (!bResult) {
        LOG_ERROR_DEV("CReportDBHelper init db, create report dbfile error or create table error.");
    } else {
        if (sqlite3_utils::sqlite3OpenDBRW(db_path.c_str(), SQLITE3_KEY, &m_handle_) == -1) {
            LOG_ERROR_DEV("CReportDBHelper init db, open log index dbfile %s failed", db_path.c_str());
            bResult = false;
        }
    }

    return bResult;
}

bool CReportDBHelper::RemoveDataFromDB(char * lpUUID) {
    if (!lpUUID) return false;
    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);
    bool bResult = false;
    sqlite3_stmt *stmt = NULL;
    do {
        std::string sql = "delete from t_report where uuid=?";
        if (sqlite3_prepare(m_handle_, sql.c_str(), sql.size(), &stmt, NULL) != SQLITE_OK) {
            LOG_ERROR_DEV("CReportDBHelper remove data, prepare del uuid[%s] from t_report failed, %s", lpUUID, sqlite3_errmsg(m_handle_));
            break;
        }
        sqlite3_bind_text(stmt, 1, lpUUID, strlen(lpUUID), SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            LOG_ERROR_DEV("CReportDBHelper remove DB data, step del uuid[%s] from t_report failed, %s", lpUUID, sqlite3_errmsg(m_handle_));
            break;
        }
        LOG_DEBUG("del uuid[%s] from t_report success", lpUUID);
        bResult = true;
    } while (false);

    if (stmt) sqlite3_finalize(stmt);

    return bResult;
}

bool CReportDBHelper::SaveDataToDB(const LOG_INFO& loginfo, char* lpUUID) {
    const char* pTmp = "insert into t_report values(?, ?, ?, ?)";
    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);

    bool bResult = false;
    sqlite3_stmt *stmt = NULL;

    do {
        if (sqlite3_prepare(m_handle_, pTmp, strlen(pTmp), &stmt, NULL) != SQLITE_OK) {
            LOG_ERROR_DEV("CReportDBHelper save DB data, prepare insert uuid[%s] into t_report failed, %s", lpUUID, sqlite3_errmsg(m_handle_));
            break;
        }
        sqlite3_bind_text(stmt, 0, lpUUID, strlen(lpUUID), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 1, loginfo.file_path.c_str(), loginfo.file_path.length(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, loginfo.file_path.c_str(), loginfo.file_path.length(), SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, loginfo.nType);
        sqlite3_bind_int(stmt, 4, loginfo.nLevel);
        sqlite3_bind_int(stmt, 5, loginfo.nTime);
        sqlite3_bind_text(stmt, 6, loginfo.rename_dir.c_str(), loginfo.rename_dir.length(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, loginfo.notice_remark.c_str(), loginfo.notice_remark.length(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, loginfo.exception_process.c_str(), loginfo.exception_process.length(), SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            LOG_ERROR_DEV("CReportDBHelper save DB data, step insert uuid[%s] into t_report failed, %s", lpUUID, sqlite3_errmsg(m_handle_));
            break;
        }

        LOG_DEBUG("insert uuid[%s] into t_report success", lpUUID);
        bResult = true;
    } while (false);

    if (stmt) sqlite3_finalize(stmt);
    return bResult;
}

bool CReportDBHelper::LoadFailData(LOG_INFO& loginfo) {
    const char* sql = "SELECT * from t_report";
    QH_THREAD::CMutexAutoLocker lck(&m_report_db_locker_);
    bool bResult = false;
    sqlite3_stmt *stmt = NULL;
    //LOG_INFO loginfo;

    do {
        if (sqlite3_prepare(m_handle_, sql, strlen(sql), &stmt, NULL) != SQLITE_OK) {
            LOG_ERROR_DEV("CReportDBHelper load DB fail data, prepare select content from t_report failed, %s", sqlite3_errmsg(m_handle_));
            break;
        }
        int rc = sqlite3_step(stmt);
        while (rc == SQLITE_ROW) {
            //char* uuid = (char *)sqlite3_column_text(stmt, 0);
            loginfo.file_path = (char *)sqlite3_column_text(stmt, 1);
            loginfo.md5 = (char *)sqlite3_column_text(stmt, 2);
            loginfo.nType = sqlite3_column_int(stmt, 3);
            loginfo.nLevel = sqlite3_column_int(stmt, 4);
            loginfo.nType = sqlite3_column_int(stmt, 5);
            loginfo.rename_dir = (char *)sqlite3_column_text(stmt, 6);
            loginfo.notice_remark = (char *)sqlite3_column_text(stmt, 7);
            loginfo.exception_process = (char *)sqlite3_column_text(stmt, 8);
            //REPORTMGRPTR->Report(loginfo);
            rc = sqlite3_step(stmt);
        }

        if (rc != SQLITE_DONE) {
            LOG_ERROR_DEV("CReportDBHelper load DB fail data, step select content from t_report failed, %s", sqlite3_errmsg(m_handle_));
            break;
        }
        bResult = true;
        LOG_DEBUG("select content from t_report success");
    } while (0);

    if (stmt) sqlite3_finalize(stmt);

    return bResult;
}
