#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <utmp.h>
#include <arpa/inet.h>

#include "common/log/log.h"
#include "system_login.h"

#define GMT_8_TZ    8*60*60

#define SYSTEM_LOGIN        1   //登录
#define SYSTEM_LOGOUT       2   //注销
#define SYSTEM_BOOT         3   //开机
#define SYSTEM_SHUTDOWN     4   //关机
#define  CE_ERROR_OK  0
#define CE_ERROR_NO_MEMORY -1
#define CE_ERROR_OPEN_FILE -2

CSystemLogin::CSystemLogin()
{
    m_mapLoginUser.clear();
    m_vecLogin.clear();
    inet_aton("0.0.0.0", (struct in_addr *)&m_nInvalidAddr);
}

CSystemLogin::~CSystemLogin()
{

}

CECode CSystemLogin::_ProcSystemFile(UTMP_INFO_T **info, int *size, int *file_seek, bool isUtmp)
{
    struct utmp st_utmp = {0};
    size_t size_utmp = sizeof(st_utmp);
    const char *file = isUtmp ? "/var/log/btmp" : WTMP_FILE;

    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        LOG_ERROR("get login info, failed to open the file. file:(%s), err:(%s)"
                , file, strerror(errno));
        return CE_ERROR_OPEN_FILE;
    }

    int start_pos = 0;
    if (*file_seek > 0) {
        start_pos = *file_seek/size_utmp;
        LOG_DEBUG("%s: file_seek = %d, start = %d", __func__, *file_seek, start_pos);
    }

    int i = 0;
    size_t j = 0;
    while(fread(&st_utmp, 1, size_utmp, fp) == size_utmp) {
        if (isUtmp)
            _DealUtmpInfo(&st_utmp);
        else
            _DealWtmpInfo(&st_utmp);

        if (start_pos > 0 && ++i == start_pos) {
            j = m_vecLogin.size();
        }
    }

    *file_seek = ftell(fp);
    fclose(fp);

    //save results
    *size = m_vecLogin.size() - j;
    if (*size <= 0)
        return CE_ERROR_OK;

    if (!isUtmp) {
        UTMP_INFO_T &temp = m_vecLogin[m_vecLogin.size() - 1];
        if (temp.type == SYSTEM_BOOT) {
            time_t t_now = time(NULL);
            if (temp.time > t_now && temp.time - GMT_8_TZ < t_now)
                temp.time -= GMT_8_TZ;
        }
    }

    *info = (UTMP_INFO_T *)malloc(sizeof(UTMP_INFO_T) * (*size));
    if (*info == NULL) {
        LOG_ERROR("malloc error, err:(%s)", strerror(errno));
        return CE_ERROR_NO_MEMORY;
    }

    UTMP_INFO_T *ptr = *info;
    for (; j < m_vecLogin.size(); j++, ptr++) {
        memcpy(ptr, &m_vecLogin[j], sizeof(UTMP_INFO_T));
        //LOG_DEBUG("%s: type[%d], user[%s], tty[%s], host[%s], time[%ld]", __func__, ptr->type, ptr->user_name,ptr->cmd_line, ptr->host, ptr->time);
    }

    return CE_ERROR_OK;
}
static bool isValidIPAddress(const char *str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str, &(sa.sin_addr)) != 0;
}
void CSystemLogin::_DealWtmpInfo(struct utmp *p_utent)
{
    UTMP_INFO_T ut = {0};

    if (!m_vecLogin.empty()) {
        UTMP_INFO_T &temp = m_vecLogin[m_vecLogin.size() - 1];
        if (temp.type == SYSTEM_BOOT && temp.time > p_utent->ut_tv.tv_sec && temp.time - GMT_8_TZ < p_utent->ut_tv.tv_sec) {
            temp.time -= GMT_8_TZ;
        }
    }

    //login
    if (p_utent->ut_type == USER_PROCESS) {
        if (strncmp(p_utent->ut_line, "pts", 3) == 0 && p_utent->ut_addr_v6[0] == (int32_t)m_nInvalidAddr) {
            // LOG_DEBUG("local login[ignored]: user = %s, tty = %s, time = %ld", p_utent->ut_name,
                    // p_utent->ut_line, p_utent->ut_tv.tv_sec);
            return;
        }

        ut.type = SYSTEM_LOGIN;
        strncpy(ut.user_name, p_utent->ut_name, sizeof(ut.user_name) - 1);
        m_mapLoginUser[p_utent->ut_line] = p_utent->ut_user;
    }
    //logout
    // } else if (p_utent->ut_type == DEAD_PROCESS) {
    //     ut.type = SYSTEM_LOGOUT;
    //     std::map<std::string, std::string>::iterator iter = m_mapLoginUser.find(p_utent->ut_line);
    //     if (iter == m_mapLoginUser.end()) {
    //         // LOG_DEBUG("unmatched logout[ignored]: user = %s, tty = %s, time = %ld", p_utent->ut_name,
    //                 // p_utent->ut_line, p_utent->ut_tv.tv_sec);
    //         return;
    //     }

    //     strncpy(ut.user_name, iter->second.c_str(), sizeof(ut.user_name) - 1);
    //     m_mapLoginUser.erase(iter);
    // //boot
    // } else if (p_utent->ut_type == BOOT_TIME) {
    //     ut.type = SYSTEM_BOOT;
    //     strncpy(ut.user_name, p_utent->ut_name, sizeof(ut.user_name) - 1);
    // //shutdown
    // } else if (p_utent->ut_type == RUN_LVL && strncmp(p_utent->ut_user, "shutdown", 8) == 0) {
    //     ut.type = SYSTEM_SHUTDOWN;
    //     strncpy(ut.user_name, p_utent->ut_name, sizeof(ut.user_name) - 1);
    // } 
    else {
        return;
    }
    if (!isValidIPAddress(p_utent->ut_host)) {
        //LOG_ERROR("Invalid IP address of login log host[%s]\n", p_utent->ut_host);
        return;
    }

    strncpy(ut.host, p_utent->ut_host, sizeof(ut.host) - 1);
    ut.time = p_utent->ut_tv.tv_sec;
    ut.result = 1;
    strncpy(ut.cmd_line, p_utent->ut_line, sizeof(ut.cmd_line) - 1);

    m_vecLogin.push_back(ut);
}



void CSystemLogin::_DealUtmpInfo(struct utmp *p_utent)
{
    UTMP_INFO_T ut = {0};
    if (!(strstr(p_utent->ut_line, "ssh") || strstr(p_utent->ut_line, "SSH"))) {
        //LOG_INFO("aaaaaaaaaa....");
        return;
    }
    if (!isValidIPAddress(p_utent->ut_host)) {
        //LOG_ERROR("Invalid IP address of login log host[%s]\n", p_utent->ut_host);
        return;
    }
    strncpy(ut.host, p_utent->ut_host, sizeof(ut.host) - 1);

    strncpy(ut.user_name, p_utent->ut_name, sizeof(ut.user_name) - 1);
    ut.time = p_utent->ut_tv.tv_sec;
    ut.result = 0;
    strncpy(ut.cmd_line, p_utent->ut_line, sizeof(ut.cmd_line) - 1);
    //LOG_INFO("xxxxxxxxxxxxxxx ut.host:%s", ut.host);
    m_vecLogin.push_back(ut);
}

CECode CSystemLogin::GetWtmpInfo(UTMP_INFO_T **info, int *size, int *file_seek)
{
    return _ProcSystemFile(info, size, file_seek, false);
}

CECode CSystemLogin::GetUtmpInfo(UTMP_INFO_T **info, int *size, int *file_seek)
{
    return _ProcSystemFile(info, size, file_seek, true);
}

void GetInfo(std::vector<UTMP_INFO_T> &vecUbmp, int type)
{
    int file_seak = 0;
    int utmpSize = 0;
    UTMP_INFO_T *utmpInfo = NULL;
    CSystemLogin syslog_ubmp;
    if (type ==1) {
        syslog_ubmp.GetUtmpInfo(&utmpInfo, &utmpSize, &file_seak);
    } else {
        syslog_ubmp.GetWtmpInfo(&utmpInfo, &utmpSize, &file_seak);
    }

    std::vector<UTMP_INFO_T>::iterator iter;
    for (iter = syslog_ubmp.m_vecLogin.begin(); iter!= syslog_ubmp.m_vecLogin.end(); iter++) {
        vecUbmp.push_back(*iter);
    }
    if (utmpInfo) {
        free(utmpInfo);
        utmpInfo = NULL;
    }
    //vecWtmp.swap(syslog_wtmp.m_vecLogin);
}

 void CSystemLogin::Clean() {
    m_vecLogin.clear();
    m_mapLoginUser.clear();
 }
