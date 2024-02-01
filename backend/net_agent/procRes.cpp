#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <iostream>
#include <fstream>
#include "common/log/log.h"
#include "common/utils/string_utils.hpp"
#include "common/utils/time_utils.hpp"
#include "common/utils/file_utils.h"

#include "procRes.h"

#define IDLE_PID        0
#define KTHREADD_PID    2
#define DEFAULT_HZ      100

CECode CProcInfo::_ParseStatusFile(const char *strPid, PROCESS_INFO_T &proc)
{
    char buff[256] = {0};
    snprintf(buff, sizeof(buff), "/proc/%s/status", strPid);
    FILE *fp = fopen(buff, "r");
    if (fp == NULL) {
        LOG_ERROR_SYS("Getting proc info, failed to open the file. file:(%s), err:(%s)"
                , buff, strerror(errno));
        return CE_ERROR_OPEN_FILE;
    }

    char name[32] = {0};
    uint32_t uiFlags = 0x1F;     //需要处理的位置1

    proc.pid = strtol(strPid, NULL, 10);
    //kthreadd本身
    if (proc.pid == KTHREADD_PID) {
        proc.ppid = IDLE_PID;   //kthreadd父进程是idle
        proc.iskthread = 1;
        proc.thread_count = 1;  //kthread线程数为1
        strcpy(proc.user_name, "root"); //kthread所属用户是root
        uiFlags ^= 0x1E;        //还有kthread没有VmRSS
    }

    //处理pid,ppid,user_name,exec_name,mem_size,thread_count
    while(uiFlags && fgets(buff, sizeof(buff), fp)) {

        if ((uiFlags & 0x1) && strncmp(buff, "Name:", 5) == 0) {
            uiFlags ^= 0x1;     //该位置0，标记已处理过，下次跳过

            if (sscanf(buff, "%31s %31s", name, proc.exec_name) != 2) {
                LOG_ERROR("Getting exec name failed: %s", buff);
            }
        } else if ((uiFlags & 0x2) && strncmp(buff, "PPid:", 5) == 0) {
            uiFlags ^= 0x2;     //该位置0，标记已处理过，下次跳过

            proc.ppid = strtol(buff + 5, NULL, 10);

            if (proc.ppid == KTHREADD_PID) {
                proc.iskthread = 1;
                proc.thread_count = 1;  //kthread线程数为1
                strcpy(proc.user_name, "root"); //kthread所属用户是root
                uiFlags ^= 0x1C;        //还有kthread没有VmRSS
            }
        } else if ((uiFlags & 0x4) && strncmp(buff, "Uid:", 4) == 0) {
            uiFlags ^= 0x4;     //该位置0，标记已处理过，下次跳过

            uint32_t uid = strtol(buff + 4, NULL, 10);
            _GetUserByUid(uid, proc);
        } else if ((uiFlags & 0x8) && strncmp(buff, "VmRSS:", 6) == 0) {
            uiFlags ^= 0x8;     //该位置0，标记已处理过，下次跳过

            proc.mem_size = strtol(buff + 6, NULL, 10);
        } else if ((uiFlags & 0x10) && strncmp(buff, "Threads:", 8) == 0) {
            uiFlags ^= 0x10;     //该位置0，标记已处理过，下次跳过

            proc.thread_count = strtol(buff + 8, NULL, 10);
        }
    }

    fclose(fp);
    return CE_ERROR_OK;
}

CECode CProcInfo::_GetSysBootTime()
{
    char buff[256] = {0};
    FILE *fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        LOG_ERROR_SYS("Getting proc info, failed to open the file. file:(/proc/stat), err:(%s)"
                , strerror(errno));
        return CE_ERROR_OPEN_FILE;
    }

    while (fgets(buff, sizeof(buff), fp)) {
        if (strncmp(buff, "btime", 5) == 0) {
            m_nSysBootTime = strtoll(buff + 5, NULL, 10);
            break;
        }
    }
    fclose(fp);

    return CE_ERROR_OK;
}

CECode CProcInfo::_ParseStatFile(const char *strPid, PROCESS_INFO_T &proc)
{
    char strFile[256] = {0};
    snprintf(strFile, sizeof(strFile), "/proc/%s/stat", strPid);
    std::ifstream file(strFile);
    if (!file) {
        LOG_ERROR_SYS("Getting proc info, failed to open the file. file:(%s), err:(%s)"
                , strFile, strerror(errno));
        return CE_ERROR_OPEN_FILE;
    }

    std::string buff = "";

    //处理priority
    if (getline(file, buff)) {
        int32_t utime = 0;
        int32_t stime = 0;
        int32_t start_time = 0;
        time_t  now_time = time(NULL);
        std::vector<std::string> key_values;

        //各系统数量不一致，不做判断
        string_utils::Split(key_values, buff, " ");
        string_utils::ToInt(key_values[17], proc.priority);
        string_utils::ToInt(key_values[13], utime);
        string_utils::ToInt(key_values[14], stime);
        string_utils::ToInt(key_values[21], start_time);
        proc.start_time = start_time/DEFAULT_HZ + m_nSysBootTime;
        time_t run_sec = now_time - m_nSysBootTime - start_time/DEFAULT_HZ;
        if (run_sec <= 0) {
            proc.cpu_percent = 0.0;
        } else {
            proc.cpu_percent = ((utime + stime)*100.0/DEFAULT_HZ)/run_sec;
        }
        //LOG_INFO("cpu_percent:%f, run_sec=%u\n",proc.cpu_percent, run_sec);
    }

    file.close();
    return CE_ERROR_OK;
}

CECode CProcInfo::_ParseCmdlineFile(const char *strPid, PROCESS_INFO_T &proc)
{
    char buff[256] = {0};
    snprintf(buff, sizeof(buff), "/proc/%s/cmdline", strPid);
    FILE *fp = fopen(buff, "r");
    if (fp == NULL) {
        LOG_ERROR_SYS("Getting proc info, failed to open the file. file:(%s), err:(%s)"
                , buff, strerror(errno));
        return CE_ERROR_OPEN_FILE;
    }

    //cmdline
    size_t len = fread(buff, 1, sizeof(buff) - 1, fp);
    size_t i = 0;

    while (i < len) {
        if (buff[i] == '\0')
            proc.cmdline[i] = ' ';
        else
            proc.cmdline[i] = buff[i];
        i++;
    }

    fclose(fp);
    return CE_ERROR_OK;
}

CECode CProcInfo::_ParseExeLinkFile(const char *strPid, PROCESS_INFO_T &proc)
{
    char buff[256] = {0};
    char target[PATH_MAX + 1] = {0};
    snprintf(buff, sizeof(buff), "/proc/%s/exe", strPid);

    int len = readlink(buff, target, PATH_MAX);
    if (len == -1) {
        LOG_DEBUG("Found a zombie: exec(%s), pid(%d)", proc.exec_name, proc.pid);
    } else {
        strncpy(proc.exec_path, target, sizeof(proc.exec_path) - 1);
    }

    return CE_ERROR_OK;
}

void CProcInfo::_InitPwEnt()
{
    struct passwd *pw = NULL;

    while ((pw = getpwent()) != 0)
        m_mapPwEnt[pw->pw_uid] = pw->pw_name;

    endpwent();
}

CECode CProcInfo::_GetUserByUid(uint32_t uid, PROCESS_INFO_T &proc)
{
    std::map<uint32_t, std::string>::iterator it = m_mapPwEnt.find(uid);
    if (it != m_mapPwEnt.end()) {
        strncpy(proc.user_name, it->second.c_str(), sizeof(proc.user_name) - 1);
    } else {
        snprintf(proc.user_name, sizeof(proc.user_name), "%u", uid);
        return CE_ERROR_DATA;
    }

    return CE_ERROR_OK;
}

CECode CProcInfo::_ScanAllProc()
{
    DIR* dir = opendir("/proc");
    if (!dir) {
        LOG_ERROR_SYS("get all process info, failed to open the file. file:(/proc), err:(%s)"
                , strerror(errno));
        return CE_ERROR_OPEN_FILE;
    }

    struct dirent* result = NULL;

    int max_pathsize = file_utils::GetPathMaxSize("/proc");
    int dirent_len = offsetof(struct dirent, d_name) + max_pathsize + 1;
    struct dirent* d = (struct dirent*)malloc(dirent_len);
    if (d == NULL) {
        LOG_ERROR("malloc error, err:(%s)", strerror(errno));
        closedir(dir);
        return CE_ERROR_NO_MEMORY;
    }

    while (readdir_r(dir, d, &result) == 0 && result != NULL) {
        if (d->d_type == DT_DIR) {
            char *ptr = d->d_name;
            while(ptr && isdigit(*ptr))
                ptr++;

            if (*ptr)
                continue;

            PROCESS_INFO_T proc = {0};
            if (_ParseStatusFile(d->d_name, proc) != CE_ERROR_OK ||
                    _ParseStatFile(d->d_name, proc) != CE_ERROR_OK)
                continue;

            if (proc.iskthread == 0) {
                _ParseCmdlineFile(d->d_name, proc);
                _ParseExeLinkFile(d->d_name, proc);
            }

            strncpy(proc.package, "--", sizeof(proc.package) - 1);
            m_mapProcInfo[proc.pid] = proc;
        }
    }

    free(d);
    closedir(dir);

    //处理parent_exec_path
    std::map<uint32_t, PROCESS_INFO_T>::iterator it;
    for (it = m_mapProcInfo.begin(); it != m_mapProcInfo.end(); it++) {
        uint32_t ppid = it->second.ppid;

        //跳过Idle进程和kthreadd进程
        if (ppid == IDLE_PID || ppid == KTHREADD_PID)
            continue;

        std::map<uint32_t, PROCESS_INFO_T>::iterator it2 = m_mapProcInfo.find(ppid);
        if (it2 == m_mapProcInfo.end()) {
            LOG_ERROR("Not found ppid(%u)", ppid);
            continue;
        }

        strncpy(it->second.parent_exec_path, it2->second.exec_path, sizeof(it->second.parent_exec_path) - 1);
    }

    return CE_ERROR_OK;
}

CECode CProcInfo::GetProcInfo(PROCESS_INFO_T** info, int *size)
{
    CECode ret = CE_ERROR_UNKNOWN;
    m_mapPwEnt.clear();
    m_mapProcInfo.clear();

    _InitPwEnt();
    _GetSysBootTime();
    ret = _ScanAllProc();
    *size = m_mapProcInfo.size();

    if (ret != CE_ERROR_OK || *size <= 0)
        return ret;

    *info = (PROCESS_INFO_T *)malloc(sizeof(PROCESS_INFO_T) * (*size));
    if (*info == NULL) {
        LOG_ERROR("malloc error, err:(%s)", strerror(errno));
        return CE_ERROR_NO_MEMORY;
    }

    PROCESS_INFO_T *ptr = *info;
    std::map<uint32_t, PROCESS_INFO_T>::iterator it;
    for (it = m_mapProcInfo.begin(); it != m_mapProcInfo.end(); it++)
        memcpy(ptr++, &(it->second), sizeof(PROCESS_INFO_T));

    return CE_ERROR_OK;
}

struct arrange_cpu
{
    bool operator()(const PROCESS_INFO_T& value1, const PROCESS_INFO_T& value2)
    {
        return value1.cpu_percent > value2.cpu_percent;
    }
};

struct arrange_mem
{
    bool operator()(const PROCESS_INFO_T& value1, const PROCESS_INFO_T& value2)
    {
        return value1.mem_size > value2.mem_size;
    }
};

CECode CProcInfo::SortCpu(std::vector<PROCESS_INFO_T> &vecInfo) {
    std::sort(vecInfo.begin(), vecInfo.end(), arrange_cpu());
    return 0;
}

CECode CProcInfo::SortMem(std::vector<PROCESS_INFO_T> &vecInfo) {
    std::sort(vecInfo.begin(), vecInfo.end(), arrange_mem());
    return 0;
}

void CProcInfo::GetSelf(std::vector<PROCESS_INFO_T> vecInfo, long &cpuPercent, long &memSize) {
    std::vector<PROCESS_INFO_T>::iterator iter_proc;
    int current_pid = getpid();
    for (iter_proc = vecInfo.begin(); iter_proc != vecInfo.end(); iter_proc++) {
        if (iter_proc->pid = current_pid) {
            cpuPercent = iter_proc->cpu_percent;
            memSize = iter_proc->mem_size;
            break;
        }
    }
}
