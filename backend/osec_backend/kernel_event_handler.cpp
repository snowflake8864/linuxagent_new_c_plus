#include "kernel_event_handler.h"
#include "common/log/log.h"
#include "common/kernel/IKernelConnector.h"
#include "common/kernel/gnHead.h"
#include "common/singleton.hpp"
#include "common/qh_thread/thread.h"
#include "common/utils/file_utils.h"
#include "common/utils/proc_info_utils.h"
#include "osec_common/global_config.hpp"
#include "osec_common/osec_pathmanager.h"
#include <pwd.h>
#include <string>
#include <map>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <dlfcn.h>
#include <dirent.h>
#include "backend/net_agent/data_operation/build_json.h"
#include "osec_common/osec_socket_utils.h"
#include "osec_common/socket_osec.h"
#include "utills.hpp"
#include "backend/net_agent/procInfo.h"
#include "backend/net_agent/ent_client_net_agent.h"
#include "report_mgr.h"
#include "process_md5_mgr.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include "thread_proc.h"
#include "thread_open_port.h"
#include "backend/net_agent/net_mgr/port_mgr.h"
#include "net_agent/policy_recv.h"
#include "backend/net_agent/net_mgr/netstate.h"

#define EVENT_MODULE_NAME "osec_name"
enum PATTERN_TYPE {
    SELF_PROTECTION_TYPE,
    LESOU_PROTECTION_TYPE,
    TAMPER_PROTECTION_TYPE
};

enum KERNEL_FLAG{
    KERNEL_FLAG_OFF_OFF = 0,   //都关
    KERNEL_FLAG_ON_OFF,        //进程开, 文件关
    KERNEL_FALG_OFF_ON,        //进程关，文件开
    KERNEL_FALG_ON             //都开
};

CZcopy_MGR *m_zcopyMgr = NULL;
ProcessMd5Mgr *m_processMd5Mgr = NULL;
CPortInfo *g_portinfo = NULL;
//#define LABEL_SDK
static std::map<std::string, int> g_mapProcessWhite;
static std::vector<POLICY_PROTECT_DIR> g_VecDirProtect;
static std::map<std::string, std::vector<std::string> > g_mapExecptDir;
static std::map<std::string, std::vector<std::string> > g_mapExecptFileType;
static std::map<std::string, int> g_mapProcessBlack;
static std::vector<POLICY_EXIPOR_PROTECT> g_VecExiportInfo;
static std::vector<PORT_REDIRECT> g_VecPortRedirect;
#define MAX_MAP_SIZE      1024*10
static CONFIG_INFO g_conf;
static int g_run_process_mode = 0;
static int g_run_file_mode = 0;
static int g_run_expoit_mode = 0;
static std::string  g_server_ip;
QH_THREAD::CMutex g_rocess_mutext;
QH_THREAD::CMutex g_dir_mutext;
QH_THREAD::CMutex g_file_flag_mutext;
QH_THREAD::CMutex g_process_flag_mutext;
QH_THREAD::CMutex g_exiport_mutext;

KernelEventHandler* KernelEventHandler::GetEventHandler()
{
    static KernelEventHandler* keh = NULL;
    if (keh) {
        return keh;
    }
    keh = new KernelEventHandler();
    if (keh == NULL) return keh;
    return keh;
}

bool SuperPopen(const std::string& cmd, std::string& cmd_buf) {
    FILE *fp = NULL;
    char buf[1024] = {0};
    fp = popen(cmd.c_str(),"r");
    if (fp == NULL) {
        return false;
    }

    int ncout = fread(buf,1,1024-1,fp);
    ncout = 100;
    cmd_buf = buf;
    pclose(fp);
    return true;
}

bool CmdlinePopen(const std::string& cmd, std::string& cmd_buf) {
    FILE *fp = NULL;
    fp = popen(cmd.c_str(),"r");
    char buf[1024] = {0};
    if (fp == NULL) {
        return false;
    }

    int ncout = fread(buf,1,1024-1,fp);
    pclose(fp);
    int i;
    for (i = 0; i < ncout - 1; i ++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    cmd_buf = buf;
    return true;
}

bool SuperSystem(const std::string& cmd, const std::string& module_name,
                 std::string& err_str) {
    if (cmd.empty()) {
        return false;
    }

    std::stringstream ss;
    bool is_ok = false;
    do {
        int status = system(cmd.c_str());
        if (status < 0) {
            ss << "do " << module_name << " cmd error: " << strerror(errno);
            break;
        }

        if (WIFEXITED(status)) {
            //取得cmdstring执行结果
            if (WEXITSTATUS(status) == 0) {
                return true;
            } else {
                ss << module_name << " cmd normal termination, exit status = "
                   << WEXITSTATUS(status);
                break;
            }
        } else if (WIFSIGNALED(status)) {
            //如果cmdstring被信号中断，取得信号值
            ss << module_name << " cmd abnormal termination, signal number = "
               << WTERMSIG(status);
            break;

        } else if (WIFSTOPPED(status)) {
            //如果cmdstring被信号暂停执行，取得信号值
            ss << module_name
               << " cmd process stopped, signal number = " << WTERMSIG(status);
            break;

        } else {
            //如果cmdstring被信号暂停执行，取得信号值
            ss << "unknown Error when do " << module_name << " cmd";
            break;
        }
        is_ok = true;
    } while (false);
    err_str = ss.str();
    return is_ok;
}

KernelEventHandler::KernelEventHandler()
{
    kernel_connector = NULL;
    handle = NULL;
    g_mapProcessWhite.clear();
    g_mapProcessBlack.clear();
    g_VecDirProtect.clear();
    g_VecExiportInfo.clear();
    m_pReport = new CNetReportMgr();
    m_processMd5Mgr = PROCMD5_MGR;
    g_conf.proc_switch = 0;
    g_conf.module_switch = 0;
    g_conf.file_switch = 0;
    // 获取基准CPU时间戳和系统时间戳
//    baseCPUTimestamp = clock();
//    baseSystemTime = time(NULL);
}

KernelEventHandler::~KernelEventHandler()
{
    if (m_TimerBusinessPort) {
        m_TimerBusinessPort->UnRegisterEvent("UpdatebusinessPort");
        delete m_TimerBusinessPort;
        m_TimerBusinessPort = NULL;
    }
    if (kernel_connector) {
        UnRegReportHandler();
        kernel_connector->Release();
        kernel_connector = NULL;
        g_mapProcessWhite.clear();
        g_mapProcessBlack.clear();
        g_VecDirProtect.clear();
        g_VecExiportInfo.clear();
    }

    if (m_pReport) {
        delete m_pReport;
        m_pReport = NULL;
    }
    OSEC_PROCES_CACHE->UnInit();
    OSEC_OPENPORT_CACHE->UnInit();
}

void KernelEventHandler::SetPlicyConf(const CONFIG_INFO &conf) {

    // int file_flag = 1;
    // int proc_flag = 1;

    QH_THREAD::CMutexAutoLocker lock(&g_process_flag_mutext);
    QH_THREAD::CMutexAutoLocker lock1(&g_file_flag_mutext);
    g_run_process_mode = conf.proc_protect;
    g_run_file_mode = conf.file_protect;
    g_run_expoit_mode = conf.extortion_protect;
    g_conf = conf;
    LOG_INFO("==========SetFlags_ex, file_switch:%d\n", g_conf.file_switch);
    //if (g_conf.file_switch || g_conf.extortion_switch || g_conf.proc_switch) 
    {
        //        SetFlags(g_conf.file_switch, g_conf.proc_switch, g_conf.extortion_switch);
        SetFlags_ex(g_conf.file_switch, g_conf.proc_switch, g_conf.extortion_switch, g_run_file_mode, g_run_process_mode, g_run_expoit_mode,\
        g_conf.syslog_inner_switch, g_conf.syslog_outer_switch, g_conf.syslog_dns_switch);
    }

    SetSelfEnable(g_conf.self_protect_switch);
    if (g_conf.open_port_switch == 0 ) {
        struct NetworkKernelPolicyInfo infoPolicy;
        memset(&infoPolicy, 0, sizeof(infoPolicy));
        infoPolicy.pol_switch = 0;
        std::vector<PORT_REDIRECT> vecData;
        vecData.clear();
        SetNetPortKernelPolicy(vecData, infoPolicy);
    }
}

void KernelEventHandler::SetPolicyDir(std::vector<POLICY_PROTECT_DIR> &vecProtectDir) {
    std::vector<POLICY_PROTECT_DIR>::iterator iter;
    QH_THREAD::CMutexAutoLocker lock(&g_dir_mutext);
    g_VecDirProtect.clear();
    g_VecDirProtect = vecProtectDir;
    g_mapExecptDir.clear();
    g_mapExecptFileType.clear();
    //        struct osec_global_dir protect_dir[50]; //zebra
    int i = 0;
    for (iter = vecProtectDir.begin(); iter != vecProtectDir.end(); iter++) {
#if 0
        if (i < 50) {
            protect_dir[i]._type = iter->type;
            strncpy(protect_dir[i].name, iter->dir.c_str(), 255);
            protect_dir[i].name_len = strlen(protect_dir[i].name);
            i ++;
        }
#endif
        std::vector<std::string> vectemp;
        vectemp.clear();
        string_utils::Split(vectemp,iter->is_white, "|");
        LOG_DEBUG("SetPolicyDir dir:%s, iter->is_white:%s",iter->dir.c_str(), iter->is_white.c_str());
        g_mapExecptDir[iter->dir] = vectemp;
        vectemp.clear();
        string_utils::Split(vectemp,iter->file_ext, "|");
        g_mapExecptFileType[iter->dir] = vectemp;
    }
#if 0
    if (kernel_connector) {
        LOG_INFO("SetPolicyDir dir to kernel\n");
        kernel_connector->SendMsgKBuf(NL_POLICY_PROTECT_RULE, (void *)(&protect_dir), sizeof(protect_dir));
    }
#endif

        {
            std::map<std::string, std::vector<std::string> >::iterator iter_map;
            for (iter_map = g_mapExecptDir.begin(); iter_map != g_mapExecptDir.end(); iter_map++) {
                std::vector<std::string>::iterator iter;
                for (iter = iter_map->second.begin(); iter != iter_map->second.end(); iter++) {
                    LOG_DEBUG("g_mapExecptDir first:%s, second:%s", iter_map->first.c_str(), iter->c_str());
                }
            }
            for (iter_map = g_mapExecptFileType.begin(); iter_map != g_mapExecptFileType.end(); iter_map++) {
                std::vector<std::string>::iterator iter;
                for (iter = iter_map->second.begin(); iter != iter_map->second.end(); iter++) {
                    LOG_DEBUG("g_mapExecptFileType first:%s, second:%s", iter_map->first.c_str(), iter->c_str());
                }
            }
        }
        LOG_DEBUG("SetPolicyDir policy recv");
    }

    void KernelEventHandler::SetFlags(const int &file_flag, const int &process_flag, const int &explore_flag) {

    //  if
        KERNEL_FLAG flag;
        flag = KERNEL_FALG_ON;
        int enable_flag = 0;
        int file_flag_temp = file_flag|explore_flag;

        if ( file_flag_temp && process_flag ) {
            enable_flag = 3;
        }
        if ( file_flag_temp && !process_flag ) {
            enable_flag = 2;
        }
        if ( !file_flag_temp && process_flag ) {
            enable_flag = 1;
        }
        if ( !file_flag_temp && !process_flag ) {
            enable_flag = 0;
        }
    LOG_INFO("========================SetFlags==================\n");
        SetSelfProtected(enable_flag);
    }

void KernelEventHandler::SetFlags_ex(const int &file_flag, 
        const int &process_flag, 
        const int &explore_flag, 
        const int &file_mode, 
        const int &process_mode, 
        const int &explore_mode,
        const int &syslog_inner_switch, 
        const int &syslog_outer_switch, 
        const int &syslog_dns_switch
        ) {  

    KERNEL_FLAG flag;
    flag = KERNEL_FALG_ON;
    int enable_flag = 0; 
    int file_flag_temp = file_flag|explore_flag;

    if ( file_flag_temp && process_flag ) {
        enable_flag = 3; 
    }    
    if ( file_flag_temp && !process_flag ) {
        enable_flag = 2; 
    }    
    if ( !file_flag_temp && process_flag ) {
        enable_flag = 1; 
    }    
    if ( !file_flag_temp && !process_flag ) {
        enable_flag = 0; 
    }    
    LOG_INFO("========================SetFlags_ex==================\n");
    enable_flag = (syslog_dns_switch<<12|syslog_outer_switch << 11 |syslog_inner_switch<<10 |process_flag<<9|file_flag<<8|explore_flag<<7|process_mode << 6|file_mode<<5|explore_mode<<4)|enable_flag;
    SetSelfProtected(enable_flag);
}


void KernelEventHandler::KillBlackProcess(const std::string &hash, const std::string &file_value) {
    std::vector<Audit_PROCESS> processinfo;
    ProcInfo::getProcessInfos(processinfo);
    std::vector<Audit_PROCESS>::iterator iter;
    for (iter = processinfo.begin(); iter != processinfo.end(); iter++) {
        LOG_DEBUG("begin tray KillBlackProcess current process :%s, hash:%s",
                iter->strExecutablePath.c_str(), hash.c_str());
        std::string file_hash ;//= md5sum::md5file(iter->strExecutablePath.c_str());

        m_processMd5Mgr->UpdateProcessMd5(iter->strExecutablePath, file_hash);
        if ( file_hash == hash) {
            LOG_DEBUG("find this process in current process list and kill");
            kill(iter->nProcessID, SIGTERM);
            struct av_process_info info;
            memset(&info, 0, sizeof(struct av_process_info));
            info.pid = iter->nProcessID;
            info.uid = 0;
            info.pwait_flag = NULL;
            strncpy(info.comm, iter->strName.c_str(), sizeof(info.comm));
            strncpy(info.path, iter->strExecutablePath.c_str(), sizeof(info.path));
            info.type = 1104;
            AuditProcessOper(&info, file_hash, 3);
            break;
        }
    }
}

void KernelEventHandler::SetPolicyProcess(std::map<std::string, std::string> &mapProcessInfo, const int &type) {
    std::map<std::string, std::string>::iterator iter;
    QH_THREAD::CMutexAutoLocker lock(&g_rocess_mutext);
    if (type == PROCEEE_WHITE_TYPE) {
        g_mapProcessWhite.clear();
        for (iter = mapProcessInfo.begin(); iter != mapProcessInfo.end(); iter++) {
            LOG_DEBUG("SetPolicyProcess white hash%s, value:%s\n", iter->first.c_str(), iter->second.c_str());
            g_mapProcessWhite[iter->first] = 0;    //基于名字
        }
    } else if (type == PROCEEE_BLACK_TYPE) {
        g_mapProcessBlack.clear();
        for (iter = mapProcessInfo.begin(); iter != mapProcessInfo.end(); iter++) {
            LOG_DEBUG("SetPolicyProcess black file：%s, hash:%s \n", iter->first.c_str(), iter->second.c_str());
            g_mapProcessBlack[iter->first] = 1;   ////基于名字
            //杀死黑名单进程
            if (g_run_process_mode == 1) 
            {
                KillBlackProcess(iter->first, iter->second);
            }
        }
    }
}

void KernelEventHandler::SetExiportDir(std::vector<POLICY_EXIPOR_PROTECT> &g_VecExiportInfo) {
    if (g_VecExiportInfo.empty()) {
        return;
    }
    int size = g_VecExiportInfo.size();
    struct osec_global_dir Exiport_dir[50];
    memset(&Exiport_dir, 0, sizeof(Exiport_dir));
    std::vector<POLICY_EXIPOR_PROTECT>::iterator iter;
    int i = 0;
    for (iter = g_VecExiportInfo.begin(); iter!= g_VecExiportInfo.end(), i<size; iter++, i++) {
        if (i>=50) {
            LOG_INFO("exiport global dir is too big and break, size:%d", size);
            break;
        }
        Exiport_dir[i]._type = iter->type;
        strncpy(Exiport_dir[i].name, iter->file_type.c_str(), 255);
        Exiport_dir[i].name_len = strlen(Exiport_dir[i].name);
        LOG_INFO("SetGlobalExiportDir dir:%s, type\n", Exiport_dir[i].name, Exiport_dir[i]._type);
    }
 
    if (kernel_connector) {
        LOG_INFO("SetExiportDir dir to kernel\n");
        kernel_connector->SendMsgKBuf(NL_POLICY_EXIPORT_RULE, (void *)(&Exiport_dir), sizeof(Exiport_dir));
    }

}

void KernelEventHandler::SetPolicyExiport(std::vector<POLICY_EXIPOR_PROTECT> &vecInfo) {
     QH_THREAD::CMutexAutoLocker lock(&g_exiport_mutext);
     g_VecExiportInfo.clear();
     g_VecExiportInfo = vecInfo;
//     SetExiportDir(g_VecExiportInfo);

}

void KernelEventHandler::SetSockMgr(CEntClientNetAgent *pSockNetAgent) {
    if (m_pReport) {
        m_pReport->Init(pSockNetAgent);
    }
    m_pSockNetAgent = pSockNetAgent;
}

int KernelEventHandler::AuditFileOper(const struct av_file_info* unlink_info, const int &level, const std::string &hash, const int &pos)
{
    int rc = 0;
    std::string str_json;
    LOG_INFO log;
    if (pos == 0) {
        log.file_path = unlink_info->path;
        if (unlink_info->dst_path[0] != '\0') {
            log.rename_dir = unlink_info->dst_path;
        }
    } else {
        log.file_path = unlink_info->dst_path;
        if (unlink_info->path[0] != '\0') {
            log.rename_dir = unlink_info->path;
        }
    }
    if (log.file_path.empty()) {
        log.file_path = unlink_info->path;
    }
#if 0
    log.exception_process = proc_info_utils::GetExecFullFileName(unlink_info->pid);
    if (log.exception_process.empty()) {
        if (unlink_info->comm[0] != '\0') {
            log.exception_process = unlink_info->comm;
            log.md5 = "-";
        }
    } else {
        log.md5 = md5sum::md5file(log.exception_process.c_str());
    }
#else
    log.exception_process = unlink_info->comm;
    //log.md5 = md5sum::md5file(unlink_info->comm);
    m_processMd5Mgr->UpdateProcessMd5(unlink_info->comm, log.md5);
#endif
    log.nType = unlink_info->type;
    log.nLevel = level;
    log.nTime = 1692760326;//time(NULL);
//    LOG_INFO("upload file log name:%s, [%s], type :%d, md5[%s].....", unlink_info->path, unlink_info->dst_path,unlink_info->type,log.md5.c_str());
    m_pReport->Report(log);
    return rc;
}

std::string get_user_name(const uid_t &uid) {

    std::string str_user = "";
    struct passwd *pwd = getpwuid(uid);
    if (pwd && pwd->pw_name) {
        str_user = pwd->pw_name;
    } else {
        str_user = "";
    }
    return str_user;
}
#if 0
std::string getProcParam(const int& strPid) {
    char buff[256] = {0};
    char cmdline[1024] = {0};
    snprintf(buff, sizeof(buff), "/proc/%d/cmdline", strPid);
    FILE *fp = fopen(buff, "r");
    if (fp == NULL) {
        return "";
    }

    //cmdline
    size_t len = fread(buff, 1, sizeof(buff) - 1, fp);
    size_t i = 0;

    while (i < len) {
        if (buff[i] == '\0')
            cmdline[i] = ' ';
        else
            cmdline[i] = buff[i];
        i++;
    }
    fclose(fp);
    return cmdline;
}
#else
std::string getProcParam(const int& strPid) 
{
    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath), "/proc/%d/cmdline", strPid);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        return "";
    }

    char cmdline[1024] = {0};
    ssize_t bytes_read = read(fd, cmdline, 1023);
    if (bytes_read == -1) {
        return "";
    }

    for (int i = 0; i < bytes_read; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    // Print the modified command line  
    close(fd);
    return cmdline;
}
#endif
#if 0
std::string getCmdLine(int pid) 
{  
    char cmd[64] = {0};
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/cmdline 2>/dev/null", pid);
    std::string cmd_result;
    CmdlinePopen(cmd, cmd_result);
    return cmd_result;
}  
#else
std::string getCmdLine(int pid) 
{  
    char filepath[256] = {0};
    snprintf(filepath, sizeof(filepath), "/proc/%d/cmdline", pid);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        return "";
    }

    char cmdline[1024] = {0};
    ssize_t bytes_read = read(fd, cmdline, 1023);
    if (bytes_read == -1) {
        return "";
    }

    for (int i = 0; i < bytes_read; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    // Print the modified command line  
    close(fd);
    std::string str(cmdline);
    return str;

}
#endif

int KernelEventHandler::AuditProcessOper(const struct av_process_info* unlink_info, const std::string &hash, const int &level, const std::string &param, const std::string &pparam)
{
    int rc = 0;
    //LOG_DEBUG("upload process log name:%s, type :%d, ppid:%d, ppname:%s.....", unlink_info->path, unlink_info->type, unlink_info->ppid, unlink_info->comm_p);
    std::vector<Audit_PROCESS> processvec;
    Audit_PROCESS process;
    process.nProcessID = unlink_info->pid;
    process.strUser = get_user_name((uid_t)unlink_info->uid);
    process.strExecutablePath = unlink_info->path;
    process.hash = hash;
    processvec.push_back(process);

  
    if (g_conf.proc_switch) {

        std::vector<LOG_INFO> loginfo;
        std::string str_json;
        LOG_INFO log;
        log.file_path = unlink_info->path;
        log.md5 = hash; 
        log.nType = unlink_info->type;
        log.nLevel = level;
        log.nTime = 1692760326;//time(NULL);
        if (unlink_info->param_pos > 0) {
            log.p_param = unlink_info->path + unlink_info->param_pos;
        }
         loginfo.push_back(log);

        if (level >0) {
            build_json::BuildAlertLogJson(loginfo, str_json);
            m_pSockNetAgent->DoUploadClientLog(str_json);
        }

        if ( (unlink_info->type == 1101) || (unlink_info->type == 1001)) {
    
            build_json::BuildAutoProcessListJson(processvec, str_json);
            m_pSockNetAgent->DoUploadProcStart(str_json);
        }
    }

    if (g_conf.syslog_process_switch)
    {

        EDRPROCESS_LOG edr_conf;
        edr_conf.uid = "";
        edr_conf.hash = hash;
        edr_conf.p_id = process.nProcessID;
#if 0
        if (param.empty()) {
            edr_conf.p_param = getProcParam(edr_conf.p_id);
        } else {
            edr_conf.p_param = param;
        }
        #else
        if (unlink_info->param_pos > 0)
            edr_conf.p_param = unlink_info->path + unlink_info->param_pos;
        #endif
        edr_conf.pp_id = unlink_info->ppid;
        edr_conf.p_dir = process.strExecutablePath;
        edr_conf.pp_dir = unlink_info->comm_p;

        std::string pp_dir_temp = proc_info_utils::GetExecFullFileName(edr_conf.pp_id);
        if (!pp_dir_temp.empty() ) {
            edr_conf.pp_dir = pp_dir_temp;
            //edr_conf.pp_hash =  md5sum::md5file(pp_dir_temp.c_str());
            m_processMd5Mgr->UpdateProcessMd5(pp_dir_temp, edr_conf.pp_hash);
            if (pparam.empty()) {
                //edr_conf.pp_param = getProcParam(edr_conf.pp_id);
                edr_conf.pp_param = getCmdLine(edr_conf.pp_id);
            } else {
                edr_conf.pp_param = pparam;
            }
        } else {
            edr_conf.pp_hash = "-";
            edr_conf.pp_param = "-";
            //edr_conf.pp_dir = "";
            LOG_DEBUG("HandleNetConnectOper can not find process in cache");
        }
     
        edr_conf.time = 1692760326;
        edr_conf.log_type = 4;   
        LOG_DEBUG("HandleEdrPrcoessOper comm:%s, pid:%d, p_param:%s, ppid:%d, ppdir:%s, pp_param:%s",
            edr_conf.p_dir.c_str(), edr_conf.p_id, edr_conf.p_param.c_str(), edr_conf.pp_id, edr_conf.pp_dir.c_str(), edr_conf.pp_param.c_str());
        m_pSockNetAgent->DoTaskUploadUdpEdrProcessSyslog(edr_conf);
    }
    return rc;
}

/* 
--------文件夹告警---------
监控模式 2001-2099
2001:文件夹新建告警
2002:文件夹删除告警
2003:文件夹修改告警
2004:文件夹读取告警
2005:文件夹重命名告警
保护模式 2101-2199
2101:文件夹新建阻止告警
2102:文件夹删除阻止告警
2103:文件夹修改阻止告警
2104:文件夹读取阻止告警
2105:文件夹重命名阻止告警

--------文件告警---------
监控模式 3001-3099
3001:文件新建告警
3002:文件删除告警
3003:文件修改告警
3004:文件读取告警
3005:文件重命名告警
保护模式 3101-3199
3101:文件新建阻止告警
3102:文件删除阻止告警
3103:文件修改阻止告警
3104:文件读取阻止告警
3105:文件重命名阻止告警

*/

static int G_WARN_LOG_TYPE[2][2][5] = {  //文件类型、监控模式、动作
    {
        {3001, 3002, 3003,3004,3005},
        {3101, 3102, 3103,3104,3105}
    },
    {
        {2001, 2002, 2003,2004,2005},
        {2101, 2102, 2103,2104,2105}
    }
};

//禁止的操作 1:读取 2:写入 4:删除 8:重命名 16:新建 [int]

#define POLICY_READ_POWER      1
#define POLICY_WRITE_POWER     1
#define POLICY_UNLINK_POWER    1
#define POLICY_RENAME_POWER    1
#define POLICY_CREATE_POWER    1

/* 
  FILE_CREATE = 0,
    FILE_REMOTE = 1,
    FILE_MODIFY = 2,
    FILE_OPEN = 3,
    FILE_RENAME = 4,

    */

static char* itoa(int num,char* str,int radix)
{/*索引表*/
    char index[]="0123456789ABCDEF";
    unsigned unum;/*中间变量*/
    int i=0,j,k;
    /*确定unum的值*/
    if(radix==10&&num<0)/*十进制负数*/
    {
        unum=(unsigned)-num;
        str[i++]='-';
    }
    else unum=(unsigned)num;/*其他情况*/
    /*转换*/
    do{
        str[i++]=index[unum%(unsigned)radix];
        unum/=radix;
       }while(unum);
    str[i]='\0';
    /*逆序*/
    if(str[0]=='-')
        k=1;/*十进制负数*/
    else
        k=0;

    for(j=k;j<=(i-1)/2;j++)
    {       char temp;
        temp=str[j];
        str[j]=str[i-1+k-j];
        str[i-1+k-j]=temp;
    }
    return str;
}

static  bool check_binary_value(int value, int bit) {
    return  (value>>bit)&0x1;
}
bool CompareWhiteProcessByPid(const int &pid, const std::string &vecWhite) {
    std::string path_process = proc_info_utils::GetExecFullFileName(pid);
    if (path_process.empty()) {
        return false;
    }
    //std::string curr_prsmd5 = md5sum::md5file(path_process.c_str());
    std::string curr_prsmd5;
    m_processMd5Mgr->UpdateProcessMd5(path_process, curr_prsmd5);
    if (vecWhite.find(curr_prsmd5) != std::string::npos) {
        return true;
    }
   
    return false;
}

bool CompareWhiteProcessByPath(const std::string &path_process, const std::string &vecWhite) {
    //std::string curr_prsmd5 = md5sum::md5file(path_process.c_str());
    std::string curr_prsmd5;
    m_processMd5Mgr->UpdateProcessMd5(path_process, curr_prsmd5);
    if (vecWhite.find(curr_prsmd5) != std::string::npos) {
        return true;
    }
   
    return false;
}

static int lesuo_match(const std::string &comm, const std::string &path, const std::string &dst_path, const int rules_idx) {


    POLICY_EXIPOR_PROTECT policy = g_VecExiportInfo[rules_idx];
    std::string curr_md5;
    m_processMd5Mgr->UpdateProcessMd5(comm, curr_md5);
    std::map<std::string, std::string>::iterator iter_map;
    for (iter_map = policy.map_comm.begin(); iter_map != policy.map_comm.end(); iter_map++) {
        if (iter_map->second == curr_md5) {
            return 1;
        }
    }
    //LOG_INFO("lesuo_match===== rule idx:%d\n", rules_idx);
    return 2;
}


static int tamper_protect_match(struct av_file_info *ppi, KernelEventHandler* handler) 
{
    POLICY_PROTECT_DIR policy = g_VecDirProtect[ppi->rules_idx];
    if (CompareWhiteProcessByPath(ppi->comm, policy.white_hash) == true)//信任进程
    {
        if (!ppi->is_monitor_mode) {
            handler->EndBoolWaiting(ppi->pwait_flag, 0);
        }
        LOG_DEBUG("g_conf.white_hash mathch return");
        return 0;
    }
    //LOG_INFO("tamper_protect_match===== rule idx:%d\n", ppi->rules_idx);
    int flag_special = -1;
    std::string close_file_pos_md5 = "";
    bool match_status = true;
    int pos_upload = 0;

    int level = 1;
    int exec_name_len = strlen(ppi->comm);
    if (ppi->protect_rw != policy.protect_rw) {
        LOG_INFO("kernel protect_rw[%x], app protect_rw[%x]\n", ppi->protect_rw, policy.protect_rw);
     }
        //LOG_INFO("kernel protect_rw[%x], app protect_rw[%x]\n", ppi->protect_rw, policy.protect_rw);
    //暂时这样处理
    LOG_INFO("tamper_protect_match===== rule idx:%d, comm[%s], type[%d], protect_rw[%x]--k[%x]\n", ppi->rules_idx, ppi->comm, ppi->type, policy.protect_rw, ppi->protect_rw);
    switch(*(uint16_t *)(ppi->comm + exec_name_len - 2)) //倒数第二个字符
    {

        case 0x6863: //may touch
            {
                if (ppi->type == FILE_MODIFY) {
                    if (strcmp(ppi->comm + exec_name_len - 6, "/touch") == 0) {
                        ppi->type = FILE_CREATE;
                        match_status = check_binary_value(policy.protect_rw, 4);
                    }                    
                }
                break;
            }
        case 0x7068: //may php 
            {

                if ((memcmp(ppi->comm + exec_name_len - 4, "/php", 3) == 0)) {
                    if ((ppi->type == FILE_RENAME) && (check_binary_value(policy.protect_rw, 4))) {
                        ppi->type = FILE_CREATE;
                        match_status = true;
                    } else if ((ppi->type == FILE_MODIFY) && (check_binary_value(policy.protect_rw, 4))) {
                        match_status = true;
                        ppi->type = FILE_CREATE;
                    } else {
                        match_status = false;
                    }
                }
                break;
            }
        case 0x6873:
            {
                //echo
                if ((memcmp(ppi->comm + exec_name_len - 4, "bash", 4) == 0)) {
                    if ((ppi->type == FILE_OPEN) && ((check_binary_value(policy.protect_rw, 0)) || (check_binary_value(policy.protect_rw, 4)))) {
                        if ((file_utils::IsFile(ppi->path) == false) && (file_utils::IsDir(ppi->path) == false)) {
                            if (check_binary_value(policy.protect_rw, 4)) {
                                ppi->type = FILE_CREATE;
                                match_status = true;
                            } else {
                                match_status =  false;
                            }
                        } else {
                            if (check_binary_value(policy.protect_rw, 0)) {
                                ppi->type = FILE_OPEN;
                                match_status = true;
                            } else {
                                match_status =  false;
                            }
                        }
                    } else if ( (ppi->type == FILE_MODIFY) && ( (check_binary_value(policy.protect_rw, 4)) || (check_binary_value(policy.protect_rw, 1)) )) {
                        if ((file_utils::IsFile(ppi->path) == false) && (file_utils::IsDir(ppi->path) == false)) {
                            ppi->type = FILE_CREATE;
                        } else {
                            ppi->type = FILE_MODIFY;
                        }
                        match_status = true;
                    } else {
                        match_status =  false;
                    }
                }
                break;
            }
        default: 
            {
                //LOG_INFO("tamper_protect_match===== rule idx:%d, comm[%s], type[%d]\n", ppi->rules_idx, ppi->comm, ppi->type);
                switch(ppi->type)
                {
                    case  FILE_CREATE:
                        {
                            match_status = check_binary_value(policy.protect_rw, 4);
                            break;
                        }
                    case FILE_REMOTE:
                        {
                            match_status = check_binary_value(policy.protect_rw, 2);
                            break;
                        }
                    case FILE_MODIFY:
                        {
                            match_status = check_binary_value(policy.protect_rw, 1);
                            break;
                        }
                    case FILE_RENAME:
                        {
                            match_status = check_binary_value(policy.protect_rw, 3);
                            break;
                        }
                    case FILE_OPEN:
                        {
                            if (check_binary_value(policy.protect_rw, 0)) {
                                if ((file_utils::IsFile(ppi->path) == false) && (file_utils::IsDir(ppi->path) == false)) {
                                    if (check_binary_value(policy.protect_rw, 4)) {
                                        ppi->type = FILE_CREATE;
                                        match_status = true;
                                    }
                                } else {
                                    ppi->type = FILE_OPEN;
                                    match_status = true;
                                }
                            } else {
                                match_status = false;
                            }

                            break;
                        }
                    default:
                        match_status = false;
                        break; 

                }
                break;
            }
    }
    int rc = 0;
    int permission = 0;
    level = 2;
    int file_mode = 0; //0:文件,1:文件夹
    if ( match_status && g_run_file_mode) {     
        permission = 1; 
        level = 3;       
    }
    if (!ppi->is_monitor_mode) {
        handler->EndBoolWaiting(ppi->pwait_flag, permission);
    }

    do {
        if (match_status) {
            //LOG_INFO("======= :%s  is_dir:%d, is_file:%d\n", ppi->path, ppi->is_dir, ppi->is_file);
            struct stat buf_file;
            //LOG_INFO("1========================= is_monitor_mode=%d\n", ppi->is_monitor_mode);
            if (access(ppi->path, F_OK) != 0) {
                //LOG_ERROR("access file :%s error is_dir:%d, is_file:%d\n", ppi->path, ppi->is_dir, ppi->is_file);

                if (strncmp(ppi->comm + exec_name_len, "/touch",6) == 0) {
                    file_mode = 0;  //文件
                    ppi->type = 0;
                } else if (strncmp(ppi->comm + exec_name_len, "/mkdir", 6) == 0) {
                    file_mode = 1; //文件夹
                } else {
                    file_mode = ppi->is_dir;
                }
            } else {
                rc = stat(ppi->path, &buf_file);
                if (rc == 0) {
					LOG_INFO("stat file :%s error is_dir:%d, is_file:%d\n", ppi->path, ppi->is_dir, ppi->is_file);
                    if (S_ISDIR(buf_file.st_mode)) {
                        file_mode = 1; //文件夹
                        if(ppi->type == FILE_MODIFY) {
                            flag_special = 0;
                        }
                    } else if (S_ISREG(buf_file.st_mode)) {
                        file_mode = 0;  //文件
                    } else {
                        file_mode = ppi->is_dir;
                    }
                } else {
                    file_mode = ppi->is_dir;
                }
            }
            LOG_INFO("HandleFileOper process:%s file_mode:%d, processinfo.is_dir:%d,processinfo.type:%d,flag_special:%d\n",\
            ppi->comm, file_mode, ppi->is_dir, ppi->type, flag_special);
            if (flag_special<0) {
                ppi->type = G_WARN_LOG_TYPE[file_mode][g_run_file_mode][ppi->type];
                rc = handler->AuditFileOper(ppi, level, close_file_pos_md5, pos_upload);
            }
        }
    } while(0);

    return 0;
}
static int HandleFileOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    int rc = 0;
    int permission = 0;
    bool match_status = false;
    int file_mode = 0; //0:文件,1:文件夹
    struct av_file_info processinfo;
    int level = 1;
    int flag_special = -1;
    int pos_upload = 0;
    int close_flag = -1;
    QH_THREAD::CMutexAutoLocker lock(&g_dir_mutext);
    size_t nLen = 0;
    struct av_file_info* ppi = (struct av_file_info*)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
    if (!ppi || nLen == 0)
        return false;

    memcpy(&processinfo, ppi, sizeof(processinfo));
    //LOG_INFO("============rules_type:%d,is_monitor_mode:%d\n",processinfo.rules_type, processinfo.is_monitor_mode);
    switch (processinfo.rules_type) {
        case LESOU_PROTECTION_TYPE:
            {
                int lesuo_match_vale = 0;
                if (g_conf.extortion_switch) {//勒索
                    int lesuo_match_vale = lesuo_match(processinfo.comm, processinfo.path, processinfo.dst_path, processinfo.rules_idx);
                    //LOG_INFO("HandleFileOper lesuo_match_vale:%d", lesuo_match_vale);
                    if (lesuo_match_vale == 2) {
                        if (g_run_expoit_mode == 0) {//监控
                            level = 2;
                            processinfo.type = 3202;
                            std::string hash_md5 = "";
                            if (!ppi->is_monitor_mode) {
                                ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 0);
                            }
                            rc = ((KernelEventHandler*)para)->AuditFileOper(&processinfo, level, hash_md5, pos_upload);
                            return rc;
                        } else {
                            //LOG_INFO("HandleFileOper lesuo_match_vale:%d, is_monitor_mode=%d", lesuo_match_vale, ppi->is_monitor_mode);
                            level = 3;
                            processinfo.type = 3201;
                            std::string hash_md5 = "";
                            if (!ppi->is_monitor_mode) {
                                ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 1);
                            }
                            rc = ((KernelEventHandler*)para)->AuditFileOper(&processinfo, level, hash_md5, pos_upload);
                            return rc;
                        }
                    } else {
                        if (!ppi->is_monitor_mode) {
                            ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 0);
                        }
                    }
                } else {
                    if (!ppi->is_monitor_mode) {
                        ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 0);
                    }
                }
                break;
            }

        case TAMPER_PROTECTION_TYPE:
            {
                if (g_conf.file_switch) {
                    tamper_protect_match(&processinfo, (KernelEventHandler*)(para));
                }
                break;
            }
        default:
            if (!ppi->is_monitor_mode) {
                ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 0);
            }

            break;
    }

    return rc;
}

//系统白名单过滤
const char* G_SYS_PROCEE_FILTER[] = {
    "/usr/bin/dbus-daemon",
    "/sbin/init",
    "/usr/sbin/NetworkManager",
    "/usr/sbin/lightdm",
    "/usr/sbin/alsactl",
    "/lib/systemd/systemd-journald",
    "/lib/systemd/systemd-udevd",
    "/lib/systemd/systemd-timesyncd",
    "/lib/systemd/systemd-logind",
    "/usr/lib/accountsservice/accounts-daemon",
    "/usr/lib/xorg/Xorg",
    "/usr/lib/policykit-1/polkitd",
    "/lib/systemd/systemd",
    "/usr/sbin/rsyslogd",
    "/bin/login",
    "/usr/bin/du",
    "/bin/dash",
    "/bin/run-parts",
    "/sbin/dhclient-script",
    "/usr/bin/sort",
    "/usr/bin/sudo",
    "/usr/bin/apt-get",
    "/usr/sbin/dpkg-preconfigure",
    "/usr/bin/dpkg-split",
    "/usr/bin/apt-extracttemplates",
    "/bin/stty",
    "/sbin/lsmod",
    "/sbin/rmmod",
    "/usr/bin/unzip",
//    "/usr/bin/dpkg",
//    "/usr/bin/rpm",
    "/usr/sbin/reboot",
    "/sbin/reboot",
    "/usr/bin/systemctl",
    "/usr/sbin/service",
    "/shutdown",
    "/halt",
    "/poweroff",
    "/systemd",
    "lsof",
    "awk",
    NULL
};

#include "common/utils/string_utils.hpp"
#define ip46_address_is_ip4(ip46)   (((ip46)->pad[0] | (ip46)->pad[1] | (ip46)->pad[2]) == 0)

#if 0
static bool is_change(const osec_network_report &last, const osec_network_report &current) {
    bool ret = false;
     if (last.dest_ip != current.dest_ip) {
        return ret;
    }

    if (last.src_ip != current.src_ip) {
        return ret;
    }

    if (last.src_port != current.src_port) {
        return ret;
    }
    
    if (last.dest_port != current.dest_port) {
        return ret;
    }
     if (last.pid != current.pid) {
        return ret;
    }
    return true;
}
#else
static bool is_change(const osec_network_report *last, const osec_network_report *current) {
    return (((last->dst.as_u64[0] ^ current->dst.as_u64[0]) || (last->dst.as_u64[1] ^ current->dst.as_u64[1]))||\
            ((last->src.as_u64[0] ^ current->src.as_u64[0]) || (last->src.as_u64[1] ^ current->src.as_u64[1]))||\
            (last->dest_port ^ current->dest_port)||(last->src_port ^ current->src_port)||\
            (last->pid ^ current->pid));
}

#endif
static int HandleNetConnectInOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    osec_network_report report;
    if (cmd == NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY) {
       
        size_t nLen = 0;

        struct netlink_netlog  *msg = (struct netlink_netlog *)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (msg == NULL||nLen == 0) {
            return false;
        }    
        if (!m_zcopyMgr)
            return false;

 
        if (!g_conf.syslog_switch) {
            return 0;
        }  
        int idx;
        struct osec_network_report* ppi = NULL, *pre_ppi = NULL;

        if (msg->max_idx == 0) {
            if (/*msg->start_idx == -1 || msg->end_idx == -1||*/ msg->start_idx >= msg->end_idx) {
                return false;
            }    

            //LOG_INFO("netlink_netlog, start_idx=%d, end_idx=%d\n", msg->start_idx, msg->end_idx); 
            for (idx = msg->start_idx; idx < msg->end_idx; idx++) {
                ppi = m_zcopyMgr->getInNetLogAuditData(idx);

                //LOG_INFO("in netlog idx:%d, ppi%p sip:%u,sport:%d, dip:%u,dport:%d\n",idx,ppi, ppi->src_ip,ppi->src_port,ppi->dest_ip,ppi->dest_port); 
                if (pre_ppi) {
                    if (!is_change(ppi, pre_ppi)) {
                        LOG_DEBUG("net is not change");
                        continue;
                    }
                }
                pre_ppi = ppi;
                memcpy(&report, ppi, sizeof(osec_network_report));

                SYSLOG_NET_LOG sys_log;
                sys_log.uid = "";
                if (ip46_address_is_ip4(&ppi->src)) {
                    in_addr dst_addr, src_addr;
                    memcpy(&dst_addr, &report.dst.ip4, 4);
                    memcpy(&src_addr, &report.src.ip4, 4);
                    sys_log.res_ip = inet_ntoa(dst_addr);
                    sys_log.source_ip = inet_ntoa(src_addr);
                    //LOG_INFO("ipv4 in netlog======[%s-->%s]\n",sys_log.res_ip.c_str(), sys_log.source_ip.c_str());
                } else {
                    in6_addr dst_addr, src_addr;
                    memcpy(&dst_addr, &report.dst.as_u8, 16);
                    memcpy(&src_addr, &report.src.as_u8, 16);
                    char str[INET6_ADDRSTRLEN];  
                    if (inet_ntop(AF_INET6, &src_addr, str, sizeof(str)) != NULL) {  
                        sys_log.source_ip = str;
                    }  
                    if (inet_ntop(AF_INET6, &dst_addr, str, sizeof(str)) != NULL) {  
                        sys_log.res_ip = str;
                    }
                    //LOG_INFO("ipv6 in netlog======[%s-->%s]\n",sys_log.res_ip.c_str(), sys_log.source_ip.c_str());
                }

                sys_log.rs_port = ntohs(report.dest_port);
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.source_port = ntohs(report.src_port);
                sys_log.p_dir = report.comm;
                /*
                   if ( (sys_log.source_ip.find("127.") != std::string::npos) || (sys_log.res_ip.find("127.") != std::string::npos)) 
                   {
                   continue; 
                   }*/
                sys_log.proto = 6;
                sys_log.log_type = 3;
                g_portinfo->getNetstatinfo();

                PORT_BUSINESS_LIST *businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.source_port);
                if (businessPort == NULL) {
                    businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.rs_port);
                }
                if (businessPort != NULL) {
                    if (businessPort->nPID > 0) {
                        report.pid = businessPort->nPID;
                    }
                    sys_log.p_id = report.pid;
                    sys_log.p_dir = businessPort->strProcessPath;
                    //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
                    if (sys_log.p_dir.size() > 0) {
                        m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
                    }
                    //LOG_DEBUG("HandleNetConnectOper in port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
                    //            LOG_INFO("in syslog idx:%d, src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", idx, sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
                    ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpNetSyslog(sys_log);

                    //} else {
                    //    sys_log.p_id = report.pid;
                }
            }
        } else {

            for (idx = 0; idx < msg->start_idx; idx++) {
                ppi = m_zcopyMgr->getInNetLogAuditData(idx);

                //LOG_INFO("in netlog idx:%d, ppi%p sip:%u,sport:%d, dip:%u,dport:%d\n",idx,ppi, ppi->src_ip,ppi->src_port,ppi->dest_ip,ppi->dest_port); 
                if (pre_ppi) {
                    if (!is_change(ppi, pre_ppi)) {
                        LOG_DEBUG("net is not change");
                        continue;
                    }
                }
                pre_ppi = ppi;
                memcpy(&report, ppi, sizeof(osec_network_report));

                SYSLOG_NET_LOG sys_log;
                sys_log.uid = "";
                if (ip46_address_is_ip4(&ppi->src)) {
                    in_addr dst_addr, src_addr;
                    memcpy(&dst_addr, &report.dst.ip4, 4);
                    memcpy(&src_addr, &report.src.ip4, 4);
                    sys_log.res_ip = inet_ntoa(dst_addr);
                    sys_log.source_ip = inet_ntoa(src_addr);
                    //LOG_INFO("ipv4 in netlog======[%s-->%s]\n",sys_log.res_ip.c_str(), sys_log.source_ip.c_str());
                } else {
                    in6_addr dst_addr, src_addr;
                    memcpy(&dst_addr, &report.dst.as_u8, 16);
                    memcpy(&src_addr, &report.src.as_u8, 16);
                    char str[INET6_ADDRSTRLEN];  
                    if (inet_ntop(AF_INET6, &src_addr, str, sizeof(str)) != NULL) {  
                        sys_log.source_ip = str;
                    }  
                    if (inet_ntop(AF_INET6, &dst_addr, str, sizeof(str)) != NULL) {  
                        sys_log.res_ip = str;
                    }
                    //LOG_INFO("ipv6 in netlog======[%s-->%s]\n",sys_log.res_ip.c_str(), sys_log.source_ip.c_str());
                }

                sys_log.rs_port = ntohs(report.dest_port);
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.source_port = ntohs(report.src_port);
                sys_log.p_dir = report.comm;
                /*
                   if ( (sys_log.source_ip.find("127.") != std::string::npos) || (sys_log.res_ip.find("127.") != std::string::npos)) 
                   {
                   continue; 
                   }*/
                sys_log.proto = 6;
                sys_log.log_type = 3;
                g_portinfo->getNetstatinfo();

                PORT_BUSINESS_LIST *businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.source_port);
                if (businessPort == NULL) {
                    businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.rs_port);
                }
                if (businessPort != NULL) {
                    if (businessPort->nPID > 0) {
                        report.pid = businessPort->nPID;
                    }
                    sys_log.p_id = report.pid;
                    sys_log.p_dir = businessPort->strProcessPath;
                    //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
                    if (sys_log.p_dir.size() > 0) {
                        m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
                    }
                    //LOG_DEBUG("HandleNetConnectOper in port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
                    //            LOG_INFO("in syslog idx:%d, src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", idx, sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
                    ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpNetSyslog(sys_log);

                    //} else {
                    //    sys_log.p_id = report.pid;
                }
            }

            for (idx = msg->end_idx; idx < msg->max_idx; idx++) {
        
                ppi = m_zcopyMgr->getInNetLogAuditData(idx);

                //LOG_INFO("in netlog idx:%d, ppi%p sip:%u,sport:%d, dip:%u,dport:%d\n",idx,ppi, ppi->src_ip,ppi->src_port,ppi->dest_ip,ppi->dest_port); 
                if (pre_ppi) {
                    if (!is_change(ppi, pre_ppi)) {
                        LOG_DEBUG("net is not change");
                        continue;
                    }
                }
                pre_ppi = ppi;
                memcpy(&report, ppi, sizeof(osec_network_report));

                SYSLOG_NET_LOG sys_log;
                sys_log.uid = "";
                if (ip46_address_is_ip4(&ppi->src)) {
                    in_addr dst_addr, src_addr;
                    memcpy(&dst_addr, &report.dst.ip4, 4);
                    memcpy(&src_addr, &report.src.ip4, 4);
                    sys_log.res_ip = inet_ntoa(dst_addr);
                    sys_log.source_ip = inet_ntoa(src_addr);
                    //LOG_INFO("ipv4 in netlog======[%s-->%s]\n",sys_log.res_ip.c_str(), sys_log.source_ip.c_str());
                } else {
                    in6_addr dst_addr, src_addr;
                    memcpy(&dst_addr, &report.dst.as_u8, 16);
                    memcpy(&src_addr, &report.src.as_u8, 16);
                    char str[INET6_ADDRSTRLEN];  
                    if (inet_ntop(AF_INET6, &src_addr, str, sizeof(str)) != NULL) {  
                        sys_log.source_ip = str;
                    }  
                    if (inet_ntop(AF_INET6, &dst_addr, str, sizeof(str)) != NULL) {  
                        sys_log.res_ip = str;
                    }
                    //LOG_INFO("ipv6 in netlog======[%s-->%s]\n",sys_log.res_ip.c_str(), sys_log.source_ip.c_str());
                }

                sys_log.rs_port = ntohs(report.dest_port);
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.source_port = ntohs(report.src_port);
                sys_log.p_dir = report.comm;
                /*
                   if ( (sys_log.source_ip.find("127.") != std::string::npos) || (sys_log.res_ip.find("127.") != std::string::npos)) 
                   {
                   continue; 
                   }*/
                sys_log.proto = 6;
                sys_log.log_type = 3;
                g_portinfo->getNetstatinfo();

                PORT_BUSINESS_LIST *businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.source_port);
                if (businessPort == NULL) {
                    businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.rs_port);
                }
                if (businessPort != NULL) {
                    if (businessPort->nPID > 0) {
                        report.pid = businessPort->nPID;
                    }
                    sys_log.p_id = report.pid;
                    sys_log.p_dir = businessPort->strProcessPath;
                    //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
                    if (sys_log.p_dir.size() > 0) {
                        m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
                    }
                    //LOG_DEBUG("HandleNetConnectOper in port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
                    //            LOG_INFO("in syslog idx:%d, src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", idx, sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
                    ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpNetSyslog(sys_log);

                    //} else {
                    //    sys_log.p_id = report.pid;
                }
            }

        }

    }


    return 0;
}

static osec_network_report g_netlaster;
static int HandleNetConnectOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para)
{
    osec_network_report_old report;
    if (cmd == NL_POLICY_NET_CONNECT_PORT_NOTIFY) {
        size_t nLen = 0;
        struct osec_network_report_old* ppi = (struct osec_network_report_old*)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (!ppi || nLen == 0)
            return 0;
        if (!g_conf.syslog_switch) {
            return 0;
        }
        if (!is_change((struct osec_network_report *)ppi, (struct osec_network_report *)&g_netlaster)) {
            LOG_DEBUG("net is not change");
            return 0;
        }
        memcpy(&report, ppi, sizeof(osec_network_report));
        //LOG_INFO("HandleNetConnectOper new");
        memcpy(&g_netlaster, ppi, sizeof(osec_network_report));
        in_addr dst_addr, src_addr;

        SYSLOG_NET_LOG sys_log;
        sys_log.uid = "";

        if (ip46_address_is_ip4(&report.src)) {
            memcpy(&dst_addr, &report.dst.ip4, 4);
            memcpy(&src_addr, &report.src.ip4, 4);
            sys_log.res_ip = inet_ntoa(dst_addr);
            sys_log.source_ip = inet_ntoa(src_addr);
        } else {

        }
        sys_log.rs_port = ntohs(report.dest_port);
        //time((long*)&sys_log.time);
        sys_log.time = 1692760326;
        sys_log.source_port = ntohs(report.src_port);
        sys_log.p_dir = report.comm;
        if (report.type == 1) {
            sys_log.proto = 6;
            sys_log.log_type = 2;
            sys_log.p_id = report.pid;
            if (sys_log.source_port<100) {
                LOG_DEBUG("out syslog src_port:%d too small\n", sys_log.source_port);
                return 0;
            }
            if (sys_log.p_id>0) {
                std::string pp_dir_temp = proc_info_utils::GetExecFullFileName(sys_log.p_id);
                if (!pp_dir_temp.empty() ) {
                    sys_log.p_dir = pp_dir_temp;
                    sys_log.hash =  md5sum::md5file(pp_dir_temp.c_str());
                }
            }
            //LOG_DEBUG("out syslog src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
            //LOG_DEBUG("HandleNetConnectOper out port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
        } else {
            sys_log.proto = 6;
            sys_log.log_type = 3;

            g_portinfo->getNetstatinfo();

            PORT_BUSINESS_LIST *businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.source_port);
            if (businessPort == NULL) {
                businessPort = g_portinfo->GetBusinessInfoByPort(sys_log.rs_port);
            }
            if (businessPort != NULL) {
                report.pid = businessPort->nPID;
                sys_log.p_id = report.pid;
                sys_log.p_dir = businessPort->strProcessPath;
                //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
                m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
                //LOG_DEBUG("HandleNetConnectOper in port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
            } else {
                sys_log.p_id = report.pid;
            }

            //LOG_INFO("in syslog src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
        }
        ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpNetSyslog(sys_log);
    }

    return 0;
}



static int HandleNetConnectOutOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    osec_network_report report;
    if (cmd == NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY) {

        size_t nLen = 0;
        struct netlink_netlog  *msg = (struct netlink_netlog *)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (msg == NULL||nLen == 0) {
            return false;
        }    

        if (!m_zcopyMgr)
            return false;


        if (!g_conf.syslog_switch) {
            return 0;
        }  

        int idx;
        struct osec_network_report* ppi = NULL, *pre_ppi = NULL;
        if (msg->max_idx == 0) {
            if (/*msg->start_idx == -1 || msg->end_idx == -1||*/ msg->start_idx >= msg->end_idx) {
                return false;
            }    


            for (idx = msg->start_idx; idx < msg->end_idx; idx++) {
                ppi = m_zcopyMgr->getOutNetLogAuditData(idx);
                if (pre_ppi) {
                    if (!is_change(ppi, pre_ppi)) {
                        LOG_DEBUG("net is not change");
                        continue;
                    }
                }
                pre_ppi = ppi;
                memcpy(&report, ppi, sizeof(osec_network_report));
                in_addr dst_addr, src_addr;
                SYSLOG_NET_LOG sys_log;
                sys_log.uid = "";
                if (ip46_address_is_ip4(&report.src)) {
                    memcpy(&dst_addr, &report.dst.ip4, 4);
                    memcpy(&src_addr, &report.src.ip4, 4);
                    sys_log.res_ip = inet_ntoa(dst_addr);
                    sys_log.source_ip = inet_ntoa(src_addr);
                }
                sys_log.rs_port = ntohs(report.dest_port);
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.source_port = ntohs(report.src_port);
                sys_log.p_dir = report.comm;
                //LOG_INFO("out syslog src_port:%d t\n", sys_log.source_port);
                /*
                   if ( (sys_log.source_ip.find("127.") != std::string::npos) || (sys_log.res_ip.find("127.") != std::string::npos)) 
                   {
                   continue; 
                   }*/
                sys_log.proto = 6;
                sys_log.log_type = 2;
                sys_log.p_id = report.pid;
                if (sys_log.p_id>0) {
                    std::string pp_dir_temp = proc_info_utils::GetExecFullFileName(sys_log.p_id);
                    if (!pp_dir_temp.empty() ) {
                        sys_log.p_dir = pp_dir_temp;
                        m_processMd5Mgr->UpdateProcessMd5(pp_dir_temp, sys_log.hash);
                    }
                }
                //LOG_INFO("out syslog idx:%d, src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", idx, sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
                //LOG_INFO("HandleNetConnectOper out port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
                ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpNetSyslog(sys_log);
            }
        } else {

            for (idx = 0; idx < msg->start_idx; idx++) {
                ppi = m_zcopyMgr->getOutNetLogAuditData(idx);
                if (pre_ppi) {
                    if (!is_change(ppi, pre_ppi)) {
                        LOG_DEBUG("net is not change");
                        continue;
                    }
                }
                pre_ppi = ppi;
                memcpy(&report, ppi, sizeof(osec_network_report));
                in_addr dst_addr, src_addr;
                SYSLOG_NET_LOG sys_log;
                sys_log.uid = "";
                if (ip46_address_is_ip4(&report.src)) {
                    memcpy(&dst_addr, &report.dst.ip4, 4);
                    memcpy(&src_addr, &report.src.ip4, 4);
                    sys_log.res_ip = inet_ntoa(dst_addr);
                    sys_log.source_ip = inet_ntoa(src_addr);
                }
                sys_log.rs_port = ntohs(report.dest_port);
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.source_port = ntohs(report.src_port);
                sys_log.p_dir = report.comm;
                //LOG_INFO("out syslog src_port:%d t\n", sys_log.source_port);
                /*
                   if ( (sys_log.source_ip.find("127.") != std::string::npos) || (sys_log.res_ip.find("127.") != std::string::npos)) 
                   {
                   continue; 
                   }*/
                sys_log.proto = 6;
                sys_log.log_type = 2;
                sys_log.p_id = report.pid;
                if (sys_log.p_id>0) {
                    std::string pp_dir_temp = proc_info_utils::GetExecFullFileName(sys_log.p_id);
                    if (!pp_dir_temp.empty() ) {
                        sys_log.p_dir = pp_dir_temp;
                        m_processMd5Mgr->UpdateProcessMd5(pp_dir_temp, sys_log.hash);
                    }
                }
                //LOG_INFO("out syslog idx:%d, src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", idx, sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
                //LOG_INFO("HandleNetConnectOper out port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
                ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpNetSyslog(sys_log);
            }


            for (idx = msg->end_idx; idx < msg->max_idx; idx++) {
                ppi = m_zcopyMgr->getOutNetLogAuditData(idx);
                if (pre_ppi) {
                    if (!is_change(ppi, pre_ppi)) {
                        LOG_DEBUG("net is not change");
                        continue;
                    }
                }
                pre_ppi = ppi;
                memcpy(&report, ppi, sizeof(osec_network_report));
                in_addr dst_addr, src_addr;
                SYSLOG_NET_LOG sys_log;
                sys_log.uid = "";
                if (ip46_address_is_ip4(&report.src)) {
                    memcpy(&dst_addr, &report.dst.ip4, 4);
                    memcpy(&src_addr, &report.src.ip4, 4);
                    sys_log.res_ip = inet_ntoa(dst_addr);
                    sys_log.source_ip = inet_ntoa(src_addr);
                }
                sys_log.rs_port = ntohs(report.dest_port);
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.source_port = ntohs(report.src_port);
                sys_log.p_dir = report.comm;
                //LOG_INFO("out syslog src_port:%d t\n", sys_log.source_port);
                /*
                   if ( (sys_log.source_ip.find("127.") != std::string::npos) || (sys_log.res_ip.find("127.") != std::string::npos)) 
                   {
                   continue; 
                   }*/
                sys_log.proto = 6;
                sys_log.log_type = 2;
                sys_log.p_id = report.pid;
                if (sys_log.p_id>0) {
                    std::string pp_dir_temp = proc_info_utils::GetExecFullFileName(sys_log.p_id);
                    if (!pp_dir_temp.empty() ) {
                        sys_log.p_dir = pp_dir_temp;
                        m_processMd5Mgr->UpdateProcessMd5(pp_dir_temp, sys_log.hash);
                    }
                }
                //LOG_INFO("out syslog idx:%d, src_port:%d, src_ip:%s, dst:%d, dst_ip:%s", idx, sys_log.source_port, sys_log.source_ip.c_str(), sys_log.rs_port,sys_log.res_ip.c_str());
                //LOG_INFO("HandleNetConnectOper out port:%d, pid:%d, dir:%s, hash:%s", sys_log.source_port, sys_log.p_id, sys_log.p_dir.c_str(), sys_log.hash.c_str());
                ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpNetSyslog(sys_log);
            }

        }
    }
    return 0;
}

static osec_dns_report g_dnslaster;
#define IPQUADS(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static int HandleNetDnsOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    osec_dns_report report;
    if (cmd == NL_POLICY_NET_DNS_PORT_NOTIFY) {
         //LOG_INFO("HandleNetDnsOper xxxxx");
        size_t nLen = 0;
        struct osec_dns_report* ppi = (struct osec_dns_report*)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (!ppi || nLen == 0)
            return 0;

        int i;
        memcpy(&report, ppi, sizeof(osec_dns_report));
        if (!is_change((const osec_network_report *)&report, (const osec_network_report *)&g_dnslaster)) {
            LOG_DEBUG("dns net is not change");
            return 0;
        }

        memcpy(&g_dnslaster, ppi, sizeof(osec_dns_report));
        in_addr dst_addr;
        memcpy(&dst_addr, &report.dest_ip, 4);
        SYLOG_DNS_LOG sys_log;
        if (strstr(report.dns_name, ".in-addr.arpa")) {
            LOG_DEBUG("dns_name:%s is not a domain");
            return 0;
        }
        sys_log.uid = "";
        sys_log.p_id = report.pid;
        sys_log.p_dir = report.comm;
        sys_log.domain_name = report.dns_name;
        if (sys_log.domain_name.empty()) {
            sys_log.res_ip = "-";
        } else {
            #if 0
            struct hostent *host = gethostbyname(report.dns_name);
            if(!host) {
                LOG_ERROR("gethostbyname dns:%s error code:%d", report.dns_name, errno);
                sys_log.res_ip = inet_ntoa(dst_addr);
            } else {
                for(int i= 0; host->h_addr_list[i]; i++) {
                    std::string ip_temp = inet_ntoa( *(struct in_addr*)host->h_addr_list[i]);
                    sys_log.res_ip += ip_temp;
                    sys_log.res_ip += ";"; 
                }
            }
            #else
            char ip_str[100];
            int n = 0;
            memset(ip_str, 0, 100);
            for (i = 0; report.ipv4[i] != 0 && i < 12; i++) {
                n += snprintf(ip_str + n, 100 - n, "%u.%u.%u.%u;", IPQUADS(report.ipv4[i]) );
            }
            sys_log.res_ip += ip_str;
            #endif
        }
        //time((long*)&sys_log.time);
        sys_log.time = 1692760326;
        sys_log.log_type = 1;
        sys_log.p_dir = proc_info_utils::GetExecFullFileName(report.pid);
        if (sys_log.p_dir.empty()) {
            sys_log.p_dir = report.comm;
        } else{
            //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
            m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
        }
        if (g_conf.syslog_dns_switch) {
            //LOG_INFO("HandleNetDnsOper comm:%s, pid:%d",report.comm, report.pid);
            if (sys_log.p_dir.empty()) {
                sys_log.p_dir = "-";
            }
            ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpDnsSyslog(sys_log);
        }
    }
    return 0;
}


#if 1
static void ipv6_to_string(const uint8_t *ipv6, char *str) 
{
    char ipv6_str[60] = {0};
    if (inet_ntop(AF_INET6, ipv6, ipv6_str, INET6_ADDRSTRLEN) == NULL) {  
        LOG_ERROR("inet_ntop failed\n");
        return;  
    }  
    int n = strlen(str);
    snprintf(str + n, 200 - n, "%s;", ipv6_str);
}  
#else
static int ipv6_to_string(uint16_t *ipv6, char *str) 
{
    int i, zero_flag = 0, zero_count = 0, n = 0;
    uint8_t *tmp;
    for (i = 0; i < 8; i++) {
        tmp = (uint8_t *)(ipv6 + i);
        if (ipv6[i] != 0) {
            if (zero_flag == 0) {
                if (tmp[0] >= 0x100) {
                    n += snprintf(str + n, 46 - n, "%02x", tmp[0]);
                } else {
                    n += snprintf(str + n, 46 - n, "%01x", tmp[0]);
                }
                n += snprintf(str + n, 46 - n, "%02x:", tmp[1]);
            } else {
                if (tmp[0] >= 0x100) {
                    n += snprintf(str + n, 46 - n, ":%02x", tmp[0]);
                } else {
                    n += snprintf(str + n, 46 - n, ":%01x", tmp[0]);
                }
                n += snprintf(str + n, 46 - n, "%02x:", tmp[1]);
            }
            zero_flag = 0;
            zero_count = 0;
        } else {
            zero_flag = 1;
            ++ zero_count;
        }
    }
    if (zero_count > 1) {
        strncat(str,  ":", 1);
        n += 1;
    }
    return n;
}
#endif

static int HandleNetDnsOper_ex(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    int rc = 0, i; 
    osec_dns_report report;
    if (cmd == NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY) {

        size_t nLen = 0;

        struct netlink_netlog  *msg = (struct netlink_netlog *)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (msg == NULL||nLen == 0) {
            return false;
        }    
        if (!m_zcopyMgr)
            return false;
        if (!g_conf.syslog_dns_switch) {
            return 0;
        }  


        //LOG_INFO("netlink_netlog, start_idx=%d, end_idx=%d\n", msg->start_idx, msg->end_idx); 
        int idx;
        struct osec_dns_report* ppi = NULL;
        if (msg->max_idx == 0) {
            if (/*msg->start_idx == -1 || msg->end_idx == -1||*/ msg->start_idx >= msg->end_idx) {
                return false;
            }    


            for (idx = msg->start_idx; idx < msg->end_idx; idx++) {
                ppi = m_zcopyMgr->getDnsLogAuditData(idx);
                if (strstr(ppi->dns_name, ".in-addr.arpa")) {
                    LOG_DEBUG("dns_name:%s is not a domain");
                    continue;
                }

                memcpy(&report, ppi, sizeof(osec_dns_report));

                SYLOG_DNS_LOG sys_log;
                sys_log.uid = "";
                sys_log.p_id = report.pid;
                sys_log.p_dir = report.comm;
                sys_log.domain_name = report.dns_name;
                if (sys_log.domain_name.empty()) {
                    sys_log.res_ip = "-";
                } else {

                    char ip_str[200];
                    int n = 0;
                    memset(ip_str, 0, 200);
                    if (report.is_ipv6 == 0) {
                        for (i = 0; report.ipv4[i] != 0 && i < report.ip_cnt; i++) {
                            n += snprintf(ip_str + n, 100 - n, "%u.%u.%u.%u;", IPQUADS(report.ipv4[i]));
                        }
                    } else {
                        for (int i = 0; i < report.ip_cnt * 16; i += 16) {  
                            //n += ipv6_to_string((uint16_t *)(report.res_ip + i), ip_str + n); 
                            ipv6_to_string((uint8_t *)report.ipv6 + i, ip_str); 
                        }  
                    }
                    sys_log.res_ip += ip_str;
                }
                //LOG_INFO("dns domain_name[%s], res ip[%s]\n", sys_log.domain_name.c_str(), sys_log.res_ip.c_str());
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.log_type = 1;
                sys_log.p_dir = proc_info_utils::GetExecFullFileName(report.pid);
                if (sys_log.p_dir.empty()) {
                    sys_log.p_dir = report.comm;
                } else{
                    //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
                    m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
                }
                //LOG_INFO("HandleNetDnsOper comm:%s, pid:%d",report.comm, report.pid);
                if (sys_log.p_dir.empty()) {
                    sys_log.p_dir = "-";
                }
                ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpDnsSyslog(sys_log);
            }
        } else {

            for (idx = 0; idx < msg->start_idx; idx++) {
                ppi = m_zcopyMgr->getDnsLogAuditData(idx);
                if (strstr(ppi->dns_name, ".in-addr.arpa")) {
                    LOG_DEBUG("dns_name:%s is not a domain");
                    continue;
                }

                memcpy(&report, ppi, sizeof(osec_dns_report));

                SYLOG_DNS_LOG sys_log;
                sys_log.uid = "";
                sys_log.p_id = report.pid;
                sys_log.p_dir = report.comm;
                sys_log.domain_name = report.dns_name;
                if (sys_log.domain_name.empty()) {
                    sys_log.res_ip = "-";
                } else {

                    char ip_str[200];
                    int n = 0;
                    memset(ip_str, 0, 200);
                    if (report.is_ipv6 == 0) {
                        for (i = 0; report.ipv4[i] != 0 && i < report.ip_cnt; i++) {
                            n += snprintf(ip_str + n, 100 - n, "%u.%u.%u.%u;", IPQUADS(report.ipv4[i]));
                        }
                    } else {
                        for (int i = 0; i < report.ip_cnt * 16; i += 16) {  
                            //n += ipv6_to_string((uint16_t *)(report.res_ip + i), ip_str + n); 
                            ipv6_to_string((uint8_t *)report.ipv6 + i, ip_str); 
                        }  
                    }
                    sys_log.res_ip += ip_str;
                }
                //LOG_INFO("dns domain_name[%s], res ip[%s]\n", sys_log.domain_name.c_str(), sys_log.res_ip.c_str());
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.log_type = 1;
                sys_log.p_dir = proc_info_utils::GetExecFullFileName(report.pid);
                if (sys_log.p_dir.empty()) {
                    sys_log.p_dir = report.comm;
                } else{
                    //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
                    m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
                }
                //LOG_INFO("HandleNetDnsOper comm:%s, pid:%d",report.comm, report.pid);
                if (sys_log.p_dir.empty()) {
                    sys_log.p_dir = "-";
                }
                ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpDnsSyslog(sys_log);
            }

            for (idx = msg->end_idx; idx < msg->max_idx; idx++) {
                ppi = m_zcopyMgr->getDnsLogAuditData(idx);
                if (strstr(ppi->dns_name, ".in-addr.arpa")) {
                    LOG_DEBUG("dns_name:%s is not a domain");
                    continue;
                }

                memcpy(&report, ppi, sizeof(osec_dns_report));

                SYLOG_DNS_LOG sys_log;
                sys_log.uid = "";
                sys_log.p_id = report.pid;
                sys_log.p_dir = report.comm;
                sys_log.domain_name = report.dns_name;
                if (sys_log.domain_name.empty()) {
                    sys_log.res_ip = "-";
                } else {

                    char ip_str[200];
                    int n = 0;
                    memset(ip_str, 0, 200);
                    if (report.is_ipv6 == 0) {
                        for (i = 0; report.ipv4[i] != 0 && i < report.ip_cnt; i++) {
                            n += snprintf(ip_str + n, 100 - n, "%u.%u.%u.%u;", IPQUADS(report.ipv4[i]));
                        }
                    } else {
                        for (int i = 0; i < report.ip_cnt * 16; i += 16) {  
                            //n += ipv6_to_string((uint16_t *)(report.res_ip + i), ip_str + n); 
                            ipv6_to_string((uint8_t *)report.ipv6 + i, ip_str); 
                        }  
                    }
                    sys_log.res_ip += ip_str;
                }
                //LOG_INFO("dns domain_name[%s], res ip[%s]\n", sys_log.domain_name.c_str(), sys_log.res_ip.c_str());
                //time((long*)&sys_log.time);
                sys_log.time = 1692760326;
                sys_log.log_type = 1;
                sys_log.p_dir = proc_info_utils::GetExecFullFileName(report.pid);
                if (sys_log.p_dir.empty()) {
                    sys_log.p_dir = report.comm;
                } else{
                    //sys_log.hash = md5sum::md5file(sys_log.p_dir.c_str());
                    m_processMd5Mgr->UpdateProcessMd5(sys_log.p_dir, sys_log.hash);
                }
                //LOG_INFO("HandleNetDnsOper comm:%s, pid:%d",report.comm, report.pid);
                if (sys_log.p_dir.empty()) {
                    sys_log.p_dir = "-";
                }
                ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadUdpDnsSyslog(sys_log);
            }

        }
    }
    return rc;
}


void KernelEventHandler::SettWhilteIpPolicy(std::vector<NET_PROTECT_IP> vecData) {
    
}

static int HandleNetPortOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    int rc = 0; 
    osec_openport_report report;
    if (cmd == NL_POLICY_NET_PORT_NOTIFY) {
        size_t nLen = 0;
        struct osec_openport_report* ppi = (struct osec_openport_report*)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (!ppi || nLen == 0)
            return 0;
        memcpy(&report, ppi, sizeof(osec_openport_report));
        std::vector<pOpenPort> vecData;
        pOpenPort openPort;
        bool find = false;
        //LOG_INFO("HandleNetPortOper kernel upload");
        openPort.time =  1692760326;//time(NULL);
        in_addr src_addr;
        memcpy(&src_addr, &report.src_ip, 4);
        openPort.attack_ip =inet_ntoa(src_addr);
        openPort.destination_ip += CPOLICYRECVMGR->m_baseinfo.ip;
        openPort.open_port = report.src_port;
        in_addr rediret_addr;
        memcpy(&rediret_addr, &report.dest_ip, 4);
        openPort.redirect_ip = inet_ntoa(rediret_addr);
        if (openPort.redirect_ip == "255.255.255.255") {
            openPort.redirect_ip = "";
        }
        openPort.redirect_port = report.dest_port;
        openPort.weight = report.type;
        find = true;
        if (find) {
            if (g_conf.serveripport.find(openPort.attack_ip) == std::string::npos) {
                vecData.push_back(openPort);
            }
            if (!vecData.empty()) {
                ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadOpenPortex(vecData);
            }
        }
    }
    return rc;
}

static int HandleNetPortOper_ex(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    int rc = 0; 
    osec_openport_report report;
    if (cmd == NL_POLICY_NET_PORT_ZCOPY_NOTIFY) {

        size_t nLen = 0;
        if (!m_zcopyMgr)
            return false;


        struct netlink_netlog  *msg = (struct netlink_netlog *)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (msg == NULL||nLen == 0) {
            return false;
        }    
        int idx;
        struct osec_openport_report* ppi = NULL;
        std::vector<pOpenPort> vecData;

        if (msg->max_idx == 0) {
            if (/*msg->start_idx == -1 || msg->end_idx == -1||*/ msg->start_idx >= msg->end_idx) {
                return false;
            }    
            //LOG_INFO("netlink_netlog, start_idx=%d, end_idx=%d\n", msg->start_idx, msg->end_idx); 
            for (idx = msg->start_idx; idx < msg->end_idx; idx++) {
                ppi = m_zcopyMgr->getOpenPortLogAuditData(idx);
                memcpy(&report, ppi, sizeof(osec_openport_report));
                //LOG_INFO("idx:%d, ppi:%p sip:%u,sport:%d, dip:%u,dport:%d\n", idx, ppi, ppi->src_ip,ppi->src_port,ppi->dest_ip,ppi->dest_port); 
                pOpenPort openPort;
                //LOG_INFO("HandleNetPortOper kernel upload");
                openPort.time =  1692760326;//time(NULL);
                in_addr src_addr;
                memcpy(&src_addr, &report.src_ip, 4);
                openPort.attack_ip =inet_ntoa(src_addr);
#if 0
                openPort.destination_ip += CPOLICYRECVMGR->m_baseinfo.ip;
#else
                in_addr dest_addr;
                memcpy(&dest_addr, &report.attack_dest_ip, 4);
                openPort.destination_ip = inet_ntoa(dest_addr);
#endif
                openPort.open_port = report.src_port;
                in_addr rediret_addr;
                memcpy(&rediret_addr, &report.dest_ip, 4);
                openPort.redirect_ip = inet_ntoa(rediret_addr);
                if (openPort.redirect_ip == "255.255.255.255") {
                    openPort.redirect_ip = "";
                }
                openPort.redirect_port = report.dest_port;
                openPort.weight = report.type;
                //LOG_INFO("================%s-->%s:%u,rediret %s:%d\n",openPort.attack_ip.c_str(), openPort.destination_ip.c_str(),openPort.open_port, openPort.redirect_ip.c_str(), openPort.redirect_port);
                //LOG_INFO("==serveripport:%s\n",g_conf.serveripport.c_str());
                //if (g_conf.serveripport.find(openPort.attack_ip) == std::string::npos) 
                {
                    vecData.push_back(openPort);
                }
            }
        } else {

            for (idx = 0; idx < msg->start_idx; idx++) {
                ppi = m_zcopyMgr->getOpenPortLogAuditData(idx);
                memcpy(&report, ppi, sizeof(osec_openport_report));
                //LOG_INFO("idx:%d, ppi:%p sip:%u,sport:%d, dip:%u,dport:%d\n", idx, ppi, ppi->src_ip,ppi->src_port,ppi->dest_ip,ppi->dest_port); 
                pOpenPort openPort;
                //LOG_INFO("HandleNetPortOper kernel upload");
                openPort.time =  1692760326;//time(NULL);
                in_addr src_addr;
                memcpy(&src_addr, &report.src_ip, 4);
                openPort.attack_ip =inet_ntoa(src_addr);
#if 0
                openPort.destination_ip += CPOLICYRECVMGR->m_baseinfo.ip;
#else
                in_addr dest_addr;
                memcpy(&dest_addr, &report.attack_dest_ip, 4);
                openPort.destination_ip = inet_ntoa(dest_addr);
#endif
                openPort.open_port = report.src_port;
                in_addr rediret_addr;
                memcpy(&rediret_addr, &report.dest_ip, 4);
                openPort.redirect_ip = inet_ntoa(rediret_addr);
                if (openPort.redirect_ip == "255.255.255.255") {
                    openPort.redirect_ip = "";
                }
                openPort.redirect_port = report.dest_port;
                openPort.weight = report.type;
                //LOG_INFO("================%s-->%s:%u,rediret %s:%d\n",openPort.attack_ip.c_str(), openPort.destination_ip.c_str(),openPort.open_port, openPort.redirect_ip.c_str(), openPort.redirect_port);
                //LOG_INFO("==serveripport:%s\n",g_conf.serveripport.c_str());
                //if (g_conf.serveripport.find(openPort.attack_ip) == std::string::npos) 
                {
                    vecData.push_back(openPort);
                }
            }

            for (idx = msg->end_idx; idx < msg->max_idx; idx++) {
                ppi = m_zcopyMgr->getOpenPortLogAuditData(idx);
                memcpy(&report, ppi, sizeof(osec_openport_report));
                //LOG_INFO("idx:%d, ppi:%p sip:%u,sport:%d, dip:%u,dport:%d\n", idx, ppi, ppi->src_ip,ppi->src_port,ppi->dest_ip,ppi->dest_port); 
                pOpenPort openPort;
                //LOG_INFO("HandleNetPortOper kernel upload");
                openPort.time =  1692760326;//time(NULL);
                in_addr src_addr;
                memcpy(&src_addr, &report.src_ip, 4);
                openPort.attack_ip =inet_ntoa(src_addr);
#if 0
                openPort.destination_ip += CPOLICYRECVMGR->m_baseinfo.ip;
#else
                in_addr dest_addr;
                memcpy(&dest_addr, &report.attack_dest_ip, 4);
                openPort.destination_ip = inet_ntoa(dest_addr);
#endif
                openPort.open_port = report.src_port;
                in_addr rediret_addr;
                memcpy(&rediret_addr, &report.dest_ip, 4);
                openPort.redirect_ip = inet_ntoa(rediret_addr);
                if (openPort.redirect_ip == "255.255.255.255") {
                    openPort.redirect_ip = "";
                }
                openPort.redirect_port = report.dest_port;
                openPort.weight = report.type;
                //LOG_INFO("================%s-->%s:%u,rediret %s:%d\n",openPort.attack_ip.c_str(), openPort.destination_ip.c_str(),openPort.open_port, openPort.redirect_ip.c_str(), openPort.redirect_port);
                //LOG_INFO("==serveripport:%s\n",g_conf.serveripport.c_str());
                //if (g_conf.serveripport.find(openPort.attack_ip) == std::string::npos) 
                {
                    vecData.push_back(openPort);
                }
            }
        }
#if 0
        if (!vecData.empty()) {
            ((KernelEventHandler*)(para))->m_pSockNetAgent->DoTaskUploadOpenPortex(vecData);
        }
#else
        if (!vecData.empty()) {
            OSEC_OPENPORT_CACHE->AddOpenPortCache(vecData);
        }
#endif
    }
    return rc;
}

int KernelEventHandler::AuditOpenPortOper(std::vector<pOpenPort> &vecData)
{
        //m_pSockNetAgent->DoTaskUploadUdpEdrProcessSyslog(edr_conf);
        //LOG_INFO("AuditOpenPortOper===size=%d\n", vecData.size());
        m_pSockNetAgent->DoTaskUploadOpenPortex(vecData);
        return 0;
}

int KernelEventHandler::Process_match_handle(struct av_process_info &procinfo ,std::string &hash_info, int& level_info) {

    int permission = 0;
    std:: map<string,int>::iterator iter;
    int match_mode = -1;  
    bool bUpload = false;
    int level = 1;
    int i = 0;
    std::string edr_process_p_aram = "";
    std::string edr_process_pp_aram = "";
    int match_system_mode = 0;
    //hash_info = md5sum::md5file(procinfo.path);

    m_processMd5Mgr->UpdateProcessMd5(procinfo.path, hash_info);
    //QH_THREAD::CMutexManualLocker lock_x(&g_rocess_mutext);
    //lock_x.lock();
    do {
        //基于进程路径
        iter = g_mapProcessWhite.find(hash_info);
        if(iter != g_mapProcessWhite.end()) {
            match_mode = 0;
        }
        iter = g_mapProcessBlack.find(hash_info);
        if(iter != g_mapProcessBlack.end()) {
            match_mode = 1;
        }
    } while(0);
    //lock_x.unlock();
    do {
        if ((g_run_process_mode == 0) && (match_mode == 0)) {         //监控模式 匹配到白名单
            permission = 0;
            level = -1;
            bUpload = false;
            break;
        } else if ((g_run_process_mode == 0) && (match_mode == 1)) {  //监控模式 匹配到黑名单
            permission = 0;
            procinfo.type = 1002;
            bUpload = true;
            level = 2;
            break;
        } else if ((g_run_process_mode == 0) && (match_mode == -1)) {  //监控模式 黑，白都没有匹配到
            permission = 0;
            procinfo.type = 1001;
            bUpload = true;
            level = 2;
            break;
        } else if ((g_run_process_mode == 1) && (match_mode == 0)) {  //保护模式 匹配到白名单
            permission = 0;
            level = -1;
            bUpload = false;
            break;
        } else if ((g_run_process_mode == 1) && (match_mode == 1)) {  //保护模式 匹配到黑名单
            permission = 1;
            procinfo.type = 1102;
            bUpload = true;
            level = 3;
            break;
        } else if ((g_run_process_mode == 1) && (match_mode == -1)) {  //保护模式 黑，白都没有匹配到
            permission = 1;
            procinfo.type = 1101;
            bUpload = true;
            level = 3;
            break;
        }
    }  while(0);
    level_info = level;
    if (permission == 1) {
        while( G_SYS_PROCEE_FILTER[i] != NULL ) {
            if (strstr(procinfo.path, G_SYS_PROCEE_FILTER[i])) {
                permission = 0; 
                match_system_mode = 1;
                LOG_DEBUG("mach system process:%s", procinfo.path);
                //bUpload = true; //上传日志与否取决于上面的逻辑
                break;
            }   
            i++;
        }
    }

//    if (match_system_mode) {
//        permission = 0;
//    }
    return permission;
}

static int getProcessCmdline(pid_t pid)
{
    char cmdline_path[128];
    memset(cmdline_path, 0, 128);
    snprintf(cmdline_path, 128, "/proc/%d/cmdline", pid);
	int fd = open(cmdline_path, O_RDWR);
    char buf[256];
    size_t nread = ::read(fd,  buf, sizeof(buf));
    if (nread > 0) {
        LOG_INFO("==[%s]\n",buf);
        if (strstr(buf, "osec")) {
            return 1;
        }
    } 
    return 0;
}

static int HandleProcessOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    int rc = 0;
    int permission = 0;
    std::string hash = "";
    // bool bUpload = false;
    struct av_process_info processinfo;
    int level = 1;
    std::string edr_process_p_aram = "";
    std::string edr_process_pp_aram = "";
    if (cmd == NL_POLICY_AV_PROCESS_EXEC_NOTIFY) {
        size_t nLen = 0;
        struct av_process_info* ppi = (struct av_process_info*)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
        if (!ppi || nLen == 0)
            return false;
        memcpy(&processinfo, ppi, sizeof(processinfo));
#if 1        
        int param_pos = strlen(processinfo.path) + 1;
        if (param_pos < 1023) {
            std::string procParam =  getCmdLine(processinfo.pid);
            if (!procParam.empty()) {
                strncpy(processinfo.path + param_pos, procParam.c_str(), 1023 - param_pos);
                processinfo.param_pos = param_pos;
//                LOG_INFO("======size=%d, [%s], path[%s],param_pos:%d\n",procParam.size(), procParam.c_str(), processinfo.path, param_pos);
            }
        }
#endif
        ppi->deny = 1;
#if 0        
        if (!ppi->is_monitor_mode) {
            int process_len = strlen(processinfo.path);
            if (process_len >= 4 ) {
                if ((strncmp(processinfo.path + process_len - 3, "rpm", 3) == 0) || (strncmp(processinfo.path + process_len - 4, "dpkg", 4) == 0)) {
                    if (getProcessCmdline(processinfo.ppid)) {
                        ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 1);
                        return 0; 
                    } 
                }
            }
        }
#endif

 //       LOG_INFO("HandleProcessOper process:%s, comm[%s],comm_p[%s]\n", ppi->path, ppi->comm,ppi->comm_p);
        if ( g_conf.proc_switch == 0)  {
  //          LOG_INFO("is only process log..\n");
            if (!ppi->is_monitor_mode)
                ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 0);
             OSEC_PROCES_CACHE->AddProcessCache(processinfo);
             return 0;
        } else {
//            LOG_INFO("process audit or process log..\n");
            if (g_run_process_mode == 0) {
                if (!ppi->is_monitor_mode)
                    ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, 0);
                 permission = ((KernelEventHandler*)para)->Process_match_handle(processinfo, hash , level);
            } else {
                permission = ((KernelEventHandler*)para)->Process_match_handle(processinfo, hash , level);
                if (!ppi->is_monitor_mode)
                    ((KernelEventHandler*)(para))->EndBoolWaiting(ppi->pwait_flag, permission);
            }
            //if (level >0)
            {
                OSEC_PROCES_CACHE->AddProcessCache(processinfo);
            }
        }
    }
    return rc;
}

static int HandleSelfProtectionOper(NLPolicyType cmd,
                          IKernelMsg* rec_kernel_msg,
                          void* para) 
{
    int rc = 0;
    int permission = 0;
    std::string hash = "";
    // bool bUpload = false;
    size_t nLen = 0;
    struct av_self_protection_info* ppi = (struct av_self_protection_info*)(rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, nLen));
    if (!ppi || nLen == 0)
        return false;
    struct Audit_SelfProtect info;
    info.param =  getCmdLine(ppi->pid);
    info.nLevel = 3;
    info.nTime = 1692760326;
    info.procDir = ppi->comm;
    info.fileDir = ppi->path;
    info.nType = ppi->type;
    info.targetDir = ppi->dst_path;
    m_processMd5Mgr->UpdateProcessMd5(ppi->comm, info.hash);
    //LOG_INFO("===HandleSelfProtectionOper==hash[%s]\n",info.hash.c_str());
    std::string str_json;
    build_json::BuildSelfProtectJson(info, str_json);
    ((KernelEventHandler*)(para))->m_pSockNetAgent->DoUploadSelfProtectLog(str_json);
    return rc;
}



int KernelEventHandler::EndBoolWaiting(void* pwait_flag, int bBool)
{
    int ret = -1;
    if (kernel_connector == NULL) {
        LOG_ERROR("kernel connector is null");
        return ret;
    }
    ret = kernel_connector->EndBoolWaiting(pwait_flag, bBool);
    if (ret) {
        LOG_ERROR("EndBoolWaiting error");
    }
    return ret;
}
int KernelEventHandler::RegReportHandler()
{
    if (kernel_connector == NULL) {
        LOG_ERROR_DEV("KernelEventHandler reg report handler, kernel_connector is NULL");
        return -1;
    }
 
    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_AV_FILE_CHANGE_NOTIFY, 3,
                                            HandleFileOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_FILE_CHANGE_NOTIFY");
        return -1;
    }

    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_AV_PROCESS_EXEC_NOTIFY, 3,
                                            HandleProcessOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_PROCESS_EXEC_NOTIFY");
        return -1;
    }
    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_AV_SELF_PROTECTION_NOTIFY, 3,
                                            HandleSelfProtectionOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_AV_SELF_PROTECTION_NOTIFY");
        return -1;
    }


    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_NET_PORT_NOTIFY, 3,
                                            HandleNetPortOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_NET_PORT_NOTIFY");
        return -1;
    }

    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_NET_PORT_ZCOPY_NOTIFY, 3,
                                            HandleNetPortOper_ex, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_NET_PORT_ZCOPY_NOTIFY");
        return -1;
    }

    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY, 3,
                                            HandleNetConnectInOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_NET_CONNECT_IN_PORT_NOTIFY");
        return -1;
    }
    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY, 3,
                                            HandleNetConnectOutOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY");
        return -1;
    }
    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                            NL_POLICY_NET_CONNECT_PORT_NOTIFY, 3,
                                            HandleNetConnectOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_NET_CONNECT_PORT_NOTIFY");
        return -1;
    }
    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                                NL_POLICY_NET_DNS_PORT_NOTIFY, 3,
                                            HandleNetDnsOper, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_NET_DNS_PORT_NOTIFY");
        return -1;
    }
    if (kernel_connector->RegCmdHandler(EVENT_MODULE_NAME,
                                                NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY, 3,
                                            HandleNetDnsOper_ex, (void*)this) != 0) {
        LOG_ERROR("KernelEventHandler reg report handler, " \
                      "reg exec cmd failed. cmd:(%s)\n", \
                      "NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY");
        return -1;
    }

    LOG_DEBUG("RegReportHandler:reg kernel recv handle callback over ...\n");
    
    return 0;
}

int KernelEventHandler::UnRegReportHandler()
{
    if (kernel_connector == NULL) {
        LOG_ERROR_DEV("UnRegReportHandler reg report handler, kernel_connector is NULL");
        return -1;
    }
 
    kernel_connector->UnRegCmdHandler(EVENT_MODULE_NAME,
                                     NL_POLICY_AV_PROCESS_EXEC_NOTIFY);
    kernel_connector->UnRegCmdHandler(EVENT_MODULE_NAME,
                                     NL_POLICY_NET_PORT_NOTIFY);
    kernel_connector->UnRegCmdHandler(EVENT_MODULE_NAME,
                                     NL_POLICY_AV_FILE_CHANGE_NOTIFY);
    kernel_connector->UnRegCmdHandler(EVENT_MODULE_NAME,
                                     NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY);
    kernel_connector->UnRegCmdHandler(EVENT_MODULE_NAME,
                                     NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY);
    kernel_connector->UnRegCmdHandler(EVENT_MODULE_NAME,
                                     NL_POLICY_NET_CONNECT_PORT_NOTIFY);
    kernel_connector->UnRegCmdHandler(EVENT_MODULE_NAME,
                                     NL_POLICY_NET_DNS_PORT_NOTIFY);
    return 0;
}


static const char * KERNEL_CONNECTOR_PATH = "/opt/osec/libOsecKernel.so";

static void unstall_osec_package(void)
{
    LOG_INFO("uninstall package osec");
    if (file_utils::IsExist("/var/log/net_info.ini")) {
        file_utils::RemoveFile("/var/log/net_info.ini");
    }
    
    file_utils::RemoveDirs("/opt/osec/.osec.txt");
    std::string cmd_string = "dpkg -P osec";
    std::string err_put = "";
    LOG_INFO("DoTaskUninstall dpkg cmd:%s", cmd_string.c_str());
    int ret = SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall dpkg cmd:%s, ret:%d", cmd_string.c_str(), ret);
    cmd_string = "rpm -qa |grep osec |xargs -I {} rpm -e {}";
    err_put = "";
    LOG_INFO("DoTaskUninstall rpm cmd:%s", cmd_string.c_str());
    ret = SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall rpm cmd:%s, ret:%d", cmd_string.c_str(), ret);

    cmd_string = "systemctl disable osec";
    err_put = "";
    LOG_INFO("DoTaskUninstall rpm cmd:%s", cmd_string.c_str());
    ret = SuperSystem(cmd_string, "uninstall",err_put);

    cmd_string = "systemctl stop osec";
    err_put = "";
    LOG_INFO("DoTaskUninstall rpm cmd:%s", cmd_string.c_str());
    ret = SuperSystem(cmd_string, "uninstall",err_put);

    cmd_string = "pkill -9 osecmonitor";
    err_put = "";
    ret = SuperSystem(cmd_string, "uninstall",err_put);

    file_utils::RemoveDirs("/opt/osec");
    LOG_INFO("DoTaskUninstall kill cmd:%s, ret:%d", cmd_string.c_str(), ret);
}


int KernelEventHandler::Init()
{
    int exit_code = EXIT_FAILURE;
    std::string str_err;
    std::string cmd_pkill = "pkill -9 socat";
    SuperSystem(cmd_pkill, "osec", str_err);

    do {
        void *pHandler = dlopen(KERNEL_CONNECTOR_PATH, RTLD_LAZY);
        if (pHandler == NULL) {
            LOG_ERROR("osec dlopen %s error, %s", KERNEL_CONNECTOR_PATH, dlerror());
            break;
        }
        FCreateInstance pCreateInstance = (FCreateInstance)dlsym(pHandler, "CreateInstance");
        if (pCreateInstance == NULL) {
            LOG_ERROR("osec dlsym CreateInstance from %s error, %s", KERNEL_CONNECTOR_PATH, dlerror());
            break;
        }

        pCreateInstance(&kernel_connector);
        if (kernel_connector == NULL) {
            LOG_ERROR("osec Createinstance from %s error!", KERNEL_CONNECTOR_PATH);
            break;
        }

        kernel_connector->SetDriverPath(PathManager::GetDriverPath().c_str(), 0);
        kernel_connector->SetConfFile(PathManager::GetDriverConfigPath().c_str());
        exit_code = kernel_connector->Init();
        if (exit_code != KERNEL_CONNECTOR_ERROR_OK) {
            LOG_ERROR("osec init error %d!", exit_code);
            //unstall_osec_package();
            CPOLICYRECVMGR->quit();
            exit_code = EXIT_FAILURE;
            exit(1);
            return exit_code;
        }
        exit_code = EXIT_SUCCESS;
        RegReportHandler();
        kernel_connector->RegisterProduct(NL_PRODUCTION_SELF);
        g_server_ip = m_pSockNetAgent->server_ip;
        if (kernel_connector) {
            int server_ip = inet_addr(g_server_ip.c_str());
            char buf[4] = {0};
            memcpy(buf, &server_ip, sizeof(buf));
            kernel_connector->SendMsgKBuf(NL_POLICY_NETWORK_SERVERIP_POLICY, (void*)buf, sizeof(defense_action));
            LOG_INFO("************ send kernel serverIP:%d, nl number:%x\n", server_ip, NL_POLICY_NETWORK_SERVERIP_POLICY);
            m_zcopyMgr = new CZcopy_MGR();
            LOG_INFO("=======m_zcopyMgr=%p\n", m_zcopyMgr);
        }
    } while (0);
    exit_code = EXIT_SUCCESS;
    OSEC_PROCES_CACHE->Init();
    OSEC_OPENPORT_CACHE->Init();
    m_portinfo = new CPortInfo();
    g_portinfo = m_portinfo;
    OSEC_PROCES_CACHE->Run();

    CPOLICYRECVMGR->signal();

    m_TimerBusinessPort = new CTimer();
    if (m_TimerBusinessPort) {
        m_TimerConf.start_time = -1;
        m_TimerConf.cycle_time = 30;
        m_TimerConf.repeat_count = -1;
        m_TimerConf.handler = std::tr1::bind(&KernelEventHandler::UpdateBusinessPortEvent, this);
        m_TimerBusinessPort->RegisterEvent(m_TimerConf, "UpdatebusinessPort");
    }

    return exit_code;
}


int KernelEventHandler::UpdateBusinessPortEvent() 
{
    if (m_portinfo->getNetstatinfo()) {

        std::map<int, PORT_BUSINESS_LIST >::iterator iter_bus;
        int port_index = 0;
        uint16_t businessPort[100] = {0};
        for (iter_bus = m_portinfo->netstat_map.begin(); iter_bus != m_portinfo->netstat_map.end(); iter_bus++) {
            if ( (iter_bus->second.nLocalPort <65535) &&  (iter_bus->second.nLocalPort >10)) {
                businessPort[port_index] = iter_bus->second.nLocalPort;
                if (++ port_index >= 100) {
                    break;
                }
            }
        }
        //LOG_INFO("netstat map size is %d, port_index = %d, data_len:%d\n", m_portinfo->netstat_map.size(), port_index, (sizeof(uint16_t) * port_index));
        if (port_index > 0) {
            SetbusinessPort(businessPort, (sizeof(uint16_t) * port_index));
        }
    }
    return 0;
}
bool KernelEventHandler::SetbusinessPort(const uint16_t *ports, const int data_len) {
    if (kernel_connector) {
        kernel_connector->SendMsgKBuf(NL_POLICY_NETWORK_BUSINESS_PORT_POLICY, (void *)ports, data_len);
    }
    return true;
}



bool KernelEventHandler::SetKernelAction(struct defense_action *action) {
    if (kernel_connector) {
        LOG_DEBUG("osec SetKernelAction action:%d", action->action);
        kernel_connector->SendMsgKBuf(NL_POLICY_DEFENSE_FILE_PROCESS_POLICY, &action, sizeof(defense_action));
    }
    return true;
}


bool KernelEventHandler::SetNetBlock(const std::vector<FirewallRule>& lstFireWall, struct NetworkKernelPolicyInfo& infoPolicy) {
    char *buf = NULL;
    int data_len = sizeof(NetworkKernelPolicyInfo);
    buf = (char *)malloc(data_len);
    if (buf == NULL) {
        LOG_ERROR("out of memory");
        return false;
    }
    memset(buf, 0, data_len);
    memcpy(buf, &infoPolicy, data_len);
    if (kernel_connector) {
        LOG_INFO("SetNetBlock  size:%d", data_len);
        kernel_connector->SendMsgKBuf((NLPolicyType)NL_POLICY_NETWORK_NETBLOCK, (void *)buf, data_len);
    }
    free(buf);
    return true;
}

void KernelEventHandler::SocatTransfer()
{
    std::string socat_path = "/opt/osec/socat";
    std::string param = "";
    std::string str_err;
    std::vector<PORT_REDIRECT>::iterator iter;
    std::string cmd_pkill = "pkill -9 socat";
    SuperSystem(cmd_pkill, "osec", str_err);
    for (iter = g_VecPortRedirect.begin(); iter != g_VecPortRedirect.end(); iter++) {
        std::string local_port = iter->source_port;
        std::string remote_ip = iter->dest_ip;
        if (remote_ip.empty()) {
            remote_ip = "127.0.0.1";
        }
        std::string remote_port = iter->dest_port;
        if (iter->protocol == "2") {
            param = socat_path + " UDP4-LISTEN:" + local_port + ",reuseaddr,fork UDP4:" + remote_ip + ":" + remote_port + "&";
        } else {
            param = socat_path + " TCP4-LISTEN:" + local_port + ",reuseaddr,fork TCP4:" + remote_ip + ":" + remote_port + "&";
        }
        SuperSystem(param, "osec", str_err);
    }
}

bool KernelEventHandler::SetNetPortKernelPolicy(const std::vector<PORT_REDIRECT> &vecData, struct NetworkKernelPolicyInfo& infoPolicy) {
    char *buf = NULL;
    g_VecPortRedirect.clear();
    g_VecPortRedirect = vecData;
    int data_len = sizeof(NetworkKernelPolicyInfo);
    buf = (char *)malloc(data_len);
    if (buf == NULL) {
        LOG_ERROR("out of memory");
        return false;
    }
    memset(buf, 0, data_len);
    memcpy(buf, &infoPolicy, data_len);
    if (kernel_connector) {
        kernel_connector->SendMsgKBuf(NL_POLICY_NETWORK_POLICY, (void *)buf, data_len);
    }
    free(buf);
    //SocatTransfer();
    return true;
}

bool KernelEventHandler::SetNetSyslogPolicy(const SYSLOG_INFO& syslog_conf_data) {
    char buf[4] = {0};
    //memcpy(buf, &syslog_conf_data.syslog_switch, sizeof(buf));
    buf[0] = !!syslog_conf_data.syslog_process_switch;
    buf[1] = !!syslog_conf_data.proc_switch;
    if (kernel_connector) {
        kernel_connector->SendMsgKBuf(NL_POLICY_NETSYSLOG_POLICY, (void *)buf, sizeof(buf));
    }
    LOG_INFO("SetNetSyslogPolicy switch:%d, proc_switch:%d\n", syslog_conf_data.syslog_process_switch, syslog_conf_data.proc_switch);
    return true;
}

//自保加白的可执行程序
void KernelEventHandler::addWhiteExes(void)
{
    const char* exes[] = {
        "/opt/osec/MagicArmor_0",
        "/opt/osec/MagicArmor_1",
        "/opt/osec/MagicArmor_2",
        "/opt/osec/MagicArmor_3",
    };

    size_t size = sizeof(exes) /
                  sizeof(exes[0]);
    
    for(size_t i = 0;i < size;i++) {
        AddWhiteProcess(exes[i]);
    }
}

bool KernelEventHandler::AddWhiteProcess(const std::string &filePath) {
    char *buf = NULL;
    int data_len = filePath.length() + 1;
    buf = (char *)malloc(data_len);
    if (buf == NULL) {
        LOG_ERROR("out of memory");
        return false;
    }
    memset(buf, 0, data_len);
    buf[0] = 'A';
    memcpy(buf + 1, filePath.c_str(), filePath.length());
    if (kernel_connector) {
        kernel_connector->SendMsgKBuf(NL_POLICY_DEFENSE_ADD_WHITE_EXE, (void *)buf, data_len);
    }
    free(buf);
    return true;
}

bool KernelEventHandler::SetSelfProtected(int status) {
    char buf[4] = {0};
    memcpy(buf, &status, sizeof(buf));
    if (kernel_connector) {
        kernel_connector->SendMsgKBuf(NL_POLICY_DEFENSE_SWITCHER, (void *)buf, sizeof(buf));
    }

    LOG_INFO("osec SetSelfProtected status:%d\n", status);
    return true;
}

bool KernelEventHandler::SetSelfEnable(int status) {
    char buf[4] = {0};
    memcpy(buf, &status, sizeof(buf));
    if (kernel_connector) {
        kernel_connector->SendMsgKBuf(NL_POLICY_SELF_SWITCHER, (void *)buf, sizeof(buf));
    }

    LOG_INFO("osec SetSelfEnable status:%d\n", status);
    return true;
}


