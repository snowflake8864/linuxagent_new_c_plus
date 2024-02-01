#include "backend/net_agent/ent_client_net_agent.h"
#include "common/log/log.h"
#include "common/uuid.h"
#include "common/pid_file.h"
#include "common/utils/proc_info_utils.h"
#include "common/utils/string_utils.hpp"
#include "common/utils/file_utils.h"
#include "common/pcinfo/pc_base_info.h"
#include "common/pcinfo/system_info.h"
#include "common/md5sum.h"
#include "common/ASFramework/ASBundleImpl.hpp"
#include "common/dependlibs/minizip/ckl_zip.h"
#include "osec_common/osec_pathmanager.h"
#include "osec_common/global_config.hpp"
#include "osec_common/socket_osec.h"
#include "osec_common/osec_socket_utils.h"
#include "osec_common/log_helper.h"
#include "backend/net_agent/net_status.h"
#include "backend/net_agent/report_data_control.hpp"
#include "backend/net_agent/policy_recv.h"
#include "backend/net_agent/data_operation/build_json.h"
#include "backend/net_agent/data_operation/parse_json.h"
#include <sstream>
#include <dlfcn.h>
#include "procInfo.h"
#include "BrowseDir_linux.h"
#include "dir_info.h"
#include "common/utils/system_utils.hpp"
#include "common/ini_parser.h"
#include "ckl_unzip.h"
#include "osec_backend/backend_mgr.h"
#include "net_mgr/port_mgr.h"
#include "net_mgr/net_mgr.h"
#include "net_mgr/firewall.h"
#include "device_mgr/udisk_monitor_mgr.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common/utils/net_utils.h"
#include "netlog_mgr.h"
#include "system_login.h"
#include "backend/net_agent/net_mgr/netstate.h"
#include "common/timer/timer_interface.hpp"
#include "common/timer/timer.h"
//#include "osec_backend/process_md5_mgr.h"
#include "procRes.h"

#define NET_AGENT_SERVICE "net_agent_client"
std::map<std::string, std::string> m_api_interface_;
static CONFIG_INFO g_conf;
#define HTTPLOGSUM  10

CEntClientNetAgent::~CEntClientNetAgent() {
    m_inited_ = false;
    m_deviceuid = "";
    m_CurrentVecUbmp.clear();
    m_CurrentVecWtmp.clear();
    if (m_TimerResource) {
        delete m_TimerResource;
        m_TimerResource = NULL;
    }
}


#include "meminfo.h"
#include "cpuinfo.h"
std::string ConvertStr(float x) 
{
    ostringstream ss;
    ss << x;
    return ss.str();
}

int CEntClientNetAgent::ResourceEvent() {
//    LOG_INFO("ResourceEvent...................");
    std::string str_send = "";
    std::string str_recv = "";
    RES_LOG res_info;
    ///实现调用资源的接口，填入res_info结构体中即可完成

    {
        //磁盘相关
        double totoal = 0.0, usedPercent = 0.0;
        getDiskInfo(totoal, usedPercent);
        res_info.hd_size = string_utils::ToString(totoal);
        res_info.hd_size += "MB";
        res_info.hd_usage = string_utils::ToString(usedPercent);
    }
    {
        //cpu相关的
        res_info.cpu_number = getCpuNum();
        double nCpuPercent = 0.0;
        CpuInfo cpu_info;
        cpu_info.getCpuInfo(&nCpuPercent);
        //nCpuPercent = cpu_info.getUsage();
        //res_info.cpu_usage = string_utils::ToString(nCpuPercent);
        res_info.cpu_usage = string_utils::ToStringDouble(nCpuPercent);
    }

    {
        //内存相关的
        unsigned long total_mem = 0;
        unsigned long mem_used = 0;
        MemInfo mem;
        mem._getMemUseState(total_mem, mem_used);
        res_info.mem_size = string_utils::ToString(total_mem);
        res_info.mem_size += "KB";
        int mem_percent = 0;
        mem.getMemInfo(&mem_percent);
        res_info.mem_usage =  string_utils::ToString(mem_percent);
    }

    {
        PROCESS_INFO_T *pRoc_res = NULL;
        int pNsize = 0;
        CProcInfo  proc_instance;
        proc_instance.GetProcInfo(&pRoc_res, &pNsize);
        std::vector<PROCESS_INFO_T> vecInfo;
        for (int i = 0; i< pNsize; i++) {
            vecInfo.push_back(pRoc_res[i]);
        }

        long self_cpu = 0, self_mem = 0 ;
        proc_instance.GetSelf(vecInfo, self_cpu, self_mem);
        res_info.self_cpu_usage = ConvertStr(self_cpu);
        res_info.self_mem_size = string_utils::ToString(self_mem);
        res_info.self_mem_size += "KB";

        proc_instance.SortCpu(vecInfo);
        if (vecInfo.size() >5) {
            for (int j = 0; j<5; j++) {
                RES_TOP res_topcpu;
                res_topcpu.cpu_usage = ConvertStr(vecInfo[j].cpu_percent);
                res_topcpu.dir = vecInfo[j].exec_path;
                res_topcpu.hash = md5sum::md5file(vecInfo[j].exec_path);
                res_topcpu.id =  string_utils::ToString(vecInfo[j].pid);
                res_topcpu.mem_size = string_utils::ToString(vecInfo[j].mem_size);
                res_topcpu.mem_size += "KB";
                res_topcpu.user = vecInfo[j].user_name;
                res_info.cpu_tops.push_back(res_topcpu);
            }
            proc_instance.SortMem(vecInfo);
            for (int j = 0; j<5; j++) {
                RES_TOP res_topcpu;
                res_topcpu.cpu_usage = ConvertStr(vecInfo[j].cpu_percent);
                res_topcpu.dir = vecInfo[j].exec_path;
                res_topcpu.hash = md5sum::md5file(vecInfo[j].exec_path);
                res_topcpu.id =  string_utils::ToString(vecInfo[j].pid);
                res_topcpu.mem_size = string_utils::ToString(vecInfo[j].mem_size);
                res_topcpu.mem_size += "KB";
                res_topcpu.user = vecInfo[j].user_name;
                res_info.mem_tops.push_back(res_topcpu);
            }
        }

        if (pRoc_res) {
            free(pRoc_res);
            pRoc_res = NULL;
        }
    }

    build_json::BuildResLogJson(res_info, str_send);
    //LOG_INFO("resource:%s", str_send.c_str());
    if (!PostDataUseURL(str_send, "puthardwareinfo",str_recv) ) {
        return 0;
    }
    return 0;
}

static void disableKernelUpgrade(void) 
{  
    // 定义文件路径  
    char filePath[] = "/etc/yum.conf";  
      
    // 打开文件  
    FILE *file = fopen(filePath, "r+");  
    if (file == NULL) {  
        LOG_ERROR("无法打开文件：%s\n", filePath);  
        return;  
    }  
  
    // 检查文件是否包含 "exclude=kernel*"  
    char line[100];  
    int found = 0;  
    rewind(file); // 确保从文件开始处读取  
    while (fgets(line, sizeof(line), file)) {  
        if (strstr(line, "exclude=kernel*")) {  
            found = 1;  
            break;  
        }  
    }  
  
    // 如果没有找到 "exclude=kernel*"，则在文件末尾写入  
    if (!found) {  
        fseek(file, 0, SEEK_END); // 定位到文件末尾  
        fprintf(file, "exclude=kernel*\n"); // 写入 "exclude=kernel*"  
    }  
  
    // 关闭文件  
    fclose(file);  
  
    LOG_INFO("已禁止 CentOS 升级内核\n");  
}  

static int isValidNetInfo(const std::string &filename)
{
    const char* expectedPrefix = "https://";
    char line[128];
    FILE* file = fopen(filename.c_str(), "r");
    int ok = 0;
    if (file == NULL) {
        LOG_INFO("无法打开文件: %s\n", filename.c_str());
        return ok;
    }

    // 逐行读取文件内容
    while (fgets(line, sizeof(line), file) != NULL) {
        // 检查 SERVER_IP 字段
        if (strncmp(line, "SERVER_IP=", 10) == 0) {
            char* serverIP = line + 10;  // 跳过 "SERVER_IP=" 前缀
            size_t serverIPLength = strlen(serverIP);

            // 检查是否以 "https://" 开头
            if (strncmp(serverIP, expectedPrefix, strlen(expectedPrefix)) == 0) {
                LOG_INFO("net_info.ini is ok\n");
                ok = 1;
            } else {
                ok = 0;
            }
            break;  // 找到 SERVER_IP 字段后停止搜索
        }
    }

    fclose(file);

    return ok;
}

bool CEntClientNetAgent::Init(CBackendMgr *pBackend) {

    if (true == m_inited_) {
        LOG_INFO("you have inited the net agent client alread.");
        return true;
    }
#if 0    
    if (file_utils::IsExist("/var/log/net_info.ini")) {
        file_utils::CopyFile("/var/log/net_info.ini", "/opt/osec/net_info.ini");
        file_utils::RemoveFile("/var/log/net_info.ini");
    }
#else
    if (file_utils::IsExist("/opt/osec/net_info.ini")) {

        if (isValidNetInfo("/opt/osec/net_info.ini") == 0) {
            if (file_utils::IsExist("/var/log/net_info.ini")) {
                file_utils::CopyFile("/var/log/net_info.ini", "/opt/osec/net_info.ini");
                LOG_INFO("cp /var/log/net_info.ini /opt/osec \n");
            }
        }
        //file_utils::RemoveFile("/var/log/net_info.ini");
    } else {
        if (file_utils::IsExist("/var/log/net_info.ini")) {
            file_utils::CopyFile("/var/log/net_info.ini", "/opt/osec/net_info.ini");
            LOG_INFO("cp /var/log/net_info.ini /opt/osec \n");
        }
    }
#endif
    if (file_utils::IsExist("/opt/osec/update")) {
        //file_utils::RemoveDirs("/opt/osec/update");
    }
    //禁止内核升级
    std::string cmd = "";
    std::string err_put = "";
    int ret = 0;
    if (access("/usr/bin/apt-mark", F_OK) == 0) {
        cmd = "/usr/bin/apt-mark apt-mark hold linux-image-generic linux-headers-generic";
        ret = system_utils::SuperSystem(cmd, "update",err_put);
        LOG_INFO("disable linux-kernel upgrade cmd:%s,ret:%d", cmd.c_str(),ret);
    }
    
    if (access("/usr/bin/yum", F_OK) == 0) {

        disableKernelUpgrade(); 
        #if 0
        cmd = "/usr/bin/yum --exclude=kernel* update";
        ret = system_utils::SuperSystem(cmd, "update",err_put);
        LOG_INFO("disable linux-kernel upgrade cmd:%s,ret:%d", cmd.c_str(),ret);
        #endif
    }
    //cmd = "systemctl start iptables";
    //system_utils::SuperSystem(cmd, "firewall", err_put);

    m_pBackend = pBackend;
    m_inited_ = true;
    LOG_INFO("InitSocketClient sucess\n");
    // init net interaction interface
    InitInterface();
    //init client info
    InitEntClient();
    m_pUdevMonitor = new CUdiskMonitorMgr();
    if (m_pUdevMonitor) {
        m_pUdevMonitor->init();
        m_pUdevMonitor->run();
    }   
    m_socketUdpFd = socket(AF_INET, SOCK_DGRAM, 0);
    if(m_socketUdpFd < 0) {
        LOG_ERROR("udpSend socket error:%d.... \n", errno);
    }
    memset(&m_addr_serv, 0, sizeof(m_addr_serv));
    std::string ip, port;
    CNETSTATUS->GetServerIPPORT(ip, port);
     LOG_INFO("get serve ip:%s,port:%s", ip.c_str(), port.c_str());
    if (!ip.empty()) {
        unsigned int pos = ip.find("://");
        if (pos != std::string::npos) {
            server_ip = ip.substr(pos + 3);
        } else {
            server_ip = "";
        }
    }
    LOG_INFO("get serve ip:%s,port:%s", server_ip.c_str(), port.c_str());
    CNETLOGMGR->Init();
    CNETLOGMGR->SetAgentClient(this);
    m_CurrentVecUbmp.clear();
    m_CurrentVecWtmp.clear();
    GetInfo(m_CurrentVecUbmp, 1);
    GetInfo(m_CurrentVecWtmp, 2);

    m_portInfo = new CPortInfo();
    Run();
    m_TimerResource = new CTimer();
    if (m_TimerResource) {
        m_TimerConf.start_time = -1;
        m_TimerConf.cycle_time = 30;
        m_TimerConf.repeat_count = -1;
        m_TimerConf.handler = std::tr1::bind(&CEntClientNetAgent::ResourceEvent, this);
        m_TimerResource->RegisterEvent(m_TimerConf, "resupload");
    }
    
    // std::string str_recv = "/opt/google/chrome/chrome";
    //socket_control::AsyncSendDataToOtherProcess(p_socket_client_mgr_, str_recv, OSEC_BUSINESS_NET_AGENT_NAME, OSEC_BACKEND_NAME, OSEC_REGISTER_FUNCTION_PROCESS_WHITE);
    return true;
}

bool CEntClientNetAgent::UnInit() {
    m_login_status_ = true;
    QH_THREAD::CThread::quit();
    QH_THREAD::CThread::join();
    CPOLICYRECVMGR->UnInit();
    if (m_pUdevMonitor) {
        m_pUdevMonitor->uninit();
        delete m_pUdevMonitor;
    }
    if (m_socketUdpFd) {
        close(m_socketUdpFd);
        m_socketUdpFd = 0;
    }    
    CNETLOGMGR->UnInit();
    return true;
}


void CEntClientNetAgent::DoSetOnlineStatus(const bool nOnline) {
    m_bOnlineClient = nOnline;
}


void CEntClientNetAgent::DealSSHlogin() {
    //test
    std::vector<UTMP_INFO_T> lastVecUbmp;
    std::vector<UTMP_INFO_T> lastVecWtmp;
    GetInfo(lastVecUbmp, 1);
    GetInfo(lastVecWtmp, 2);
    //LOG_INFO("DealSSHlogin run");

    if (m_CurrentVecUbmp.size() < lastVecUbmp.size()) {
        size_t nlen = m_CurrentVecUbmp.size();
        for (size_t i = nlen; i<lastVecUbmp.size(); i++ ) {
            UTMP_INFO_T iter = lastVecUbmp.at(i);
            SYLOG_SSH_LOG sys_log;
            sys_log.ip = iter.host;
            sys_log.log_type = 5;
            sys_log.status = iter.result;
            sys_log.username = iter.user_name;
            sys_log.time = iter.time;
            sys_log.type = "SSH";
            DoTaskUploadSSHSyslog(sys_log);
        }
        m_CurrentVecUbmp = lastVecUbmp;
    }

    if (m_CurrentVecWtmp.size() < lastVecWtmp.size()) {
        size_t nlen = m_CurrentVecWtmp.size();
        for (size_t i = nlen; i<lastVecWtmp.size(); i++ ) {
            UTMP_INFO_T iter = lastVecWtmp.at(i);
            SYLOG_SSH_LOG sys_log;
            sys_log.ip = iter.host;
            sys_log.log_type = 5;
            sys_log.status = iter.result;
            sys_log.username = iter.user_name;
            sys_log.time = iter.time;
            sys_log.type = "SSH";
            DoTaskUploadSSHSyslog(sys_log);
        }
        m_CurrentVecWtmp = lastVecWtmp;
    } 
}

bool CEntClientNetAgent::InitInterface() {
    m_api_interface_["download_white"]           = "v1/getprocwl";
    m_api_interface_["getconf"]                  = "v1/getconf";
    m_api_interface_["getdirpolicy"]             = "v1/getdirpolicy";
    m_api_interface_["upload_process"]           = "v1/uploadproc";
    m_api_interface_["upload_conf"]              = "v1/putconf";
    m_api_interface_["upload_dir"]               = "v1/putdir";
    m_api_interface_["upload_log"]               = "v1/alertupload";
    m_api_interface_["update"]                   = "v1/download";
    m_api_interface_["getdirinfo"]               = "v1/getdirinfo";
    m_api_interface_["download_black"]           = "v1/getprocbl";
    m_api_interface_["autouploadprocess"]        = "v1/autouploadprocess";
    m_api_interface_["module/process"]           = "v1/module/process";  
    m_api_interface_["getprotect"]               = "v1/getprotect";  
    m_api_interface_["upload/proc/module"]       = "v1/upload/proc/module";  
    m_api_interface_["upload/allproc/module"]    = "v1/upload/allproc/module";
    m_api_interface_["module/white/list"]        = "v1/module/white/list"; 
    m_api_interface_["module/black/list"]        = "v1/module/black/list"; 
    m_api_interface_["uninstall"]                = "v1/uninstall"; 
    m_api_interface_["getvirtualport"]           = "v1/getvirtualport"; 
    m_api_interface_["upserviceport"]            = "v1/upserviceport"; 
    m_api_interface_["upOpenPort"]               = "v1/upOpenPort"; 
    m_api_interface_["getPlugging"]              = "v1/getPlugging"; 
    m_api_interface_["getipwhitelist"]           = "v1/getipwhitelist"; 
    m_api_interface_["getipblacklist"]           = "v1/getipblacklist";
    m_api_interface_["getwhiteperipherals"]      = "v1/getwhiteperipherals";
    m_api_interface_["getblackperipherals"]      = "v1/getblackperipherals";
    m_api_interface_["addperipherals"]           = "v1/addperipherals";
    m_api_interface_["getdraw"]                  = "v1/getdraw";
    m_api_interface_["uploaddraw"]               = "v1/uploaddraw";
    m_api_interface_["getSyslogConf"]            = "v1/getSyslogConf";
    m_api_interface_["closetask"]                = "v1/closetask";
    m_api_interface_["gettrustdir"]              = "v1/gettrustdir";
    m_api_interface_["putlognetworkinner"]       = "v1/putlognetworkinner";
    m_api_interface_["putlognetworkouter"]       = "v1/putlognetworkouter";
    m_api_interface_["putlogprocess"]            = "v1/putlogprocess";
    m_api_interface_["putlogdns"]                = "v1/putlogdns";
    m_api_interface_["upload/suffix/exe"]        = "v1/upload/suffix/exe";
    m_api_interface_["putsyslog"]                = "v1/putsyslog";
    m_api_interface_["puthardwareinfo"]          = "v1/puthardwareinfo";
    
    return true;
}

bool CEntClientNetAgent::InitEntClient() {
    // set client necessary info
    SetClientInfoIntoConfig();
    // init net status mgr
    CNETSTATUS->Init();
    // init policy mgr
    CPOLICYRECVMGR->Init(this, this->RunTaskCallBack);
    CPOLICYRECVMGR->Run();

    {
        std::string strIP;
        std::string strPort;
        CNETSTATUS->GetServerIPPORT(strIP, strPort);
        parse_json::SetServerIp(strIP, strPort);
    }
    return true;
}

void CEntClientNetAgent::RunTaskCallBack(void* pParam, TASK_TYPE type) {
    CEntClientNetAgent *pThis = (CEntClientNetAgent*)pParam;
    if (type == TASK_UPLOAD_PROCESS) {
        pThis->DoTaskUploadProcess();
    } else if (type == TASK_UPDATE) {
        pThis->DoTaskUpdate();
    } else if (type == TASK_UPLOAD_DIR) {
        pThis->DoScanDir();
        //pThis->DoTaskUploadPDirTree();
    } else if (type == TASK_DOWN_WHITE) { 
        pThis->DoTaskDownLoadProcessWhite();
    } else if (type == TASK_DOWN_CONF) {
        pThis->DoTaskGetConf();
    } else if (type == TASK_UPLOAD_CONF) {
        pThis->DoTaskUploadConf();
    } else if (type == TASK_DOWN_DIR_POLICY) {
        pThis->DoTaskDownLoadDirPoicy();
    } else if (type == TASK_DOWN_BLACK) {
        pThis->DoTaskDownLoadProcessBlack();
    } else if (type == TASK_DOWN_EXTORT) {
        pThis->DoTaskDownExtort();
    } else if (type == TASK_UPLOAD_PROCESS_MODULE) {
        pThis->DoTaskDownProcessModule();
    } else if (type == TASK_UPLOAD_ALL_PROCESS_MODULE) {
        pThis->DoTaskDownAllProcessModule();
    } else if (type == TASK_UPLOAD_PROCESS_WHITE_MODULE) {
        pThis->DoTaskDownProcessWhiteModule();
    } else if (type == TASK_UPLOAD_PROCESS_BLACK_MODULE) {
        pThis->DoTaskDownProcessBlackModule();
    } else if (type == TASK_UNINSTALL) {
        pThis->DoTaskUninstall();
    } else if (type == TASK_UPLOAD_PORT) {
        pThis->DoTaskUploadPort();
    } else if (type == TASK_DOWN_VIRTUAL_PORT) {
        pThis->DoTaskDownPortPolicy();
    } else if (type == TASK_DOWN_NETBLOACK_POLICY) {
        pThis->DoTaskgetPlugging();
    } else if (type == TASK_DOWN_WHITE_IP_POLICY) {
        pThis->DoTaskgetipwhitelist();
    } else if (type == TASK_DOWN_BLACK_IP_POLICY) {
        pThis->DoTaskgetipblacklist();
    } else if (type == TASK_getwhiteperipherals) {
        pThis->DoTaskgetwhiteperipherals();
    } else if (type == TASK_getblackperipherals) {
        pThis->DoTaskgetblackperipherals();
    } else if (type == TASK_DOWN_USB_UPLOAD) {
        pThis->DoTaskUsbUpload();
    } else if (type == TASK_DOWN_USB_DOWN) {
        pThis->DoTaskUsbDown();
    } else if (type == TASK_UPLOADSAMPLE) {
        pThis->DoTaskUploadSample();
    } else if (type == TASK_SYSLOG_ENABLE) {//不用了
        //pThis->DoTaskSysLogEnable();
    } else if (type == TASK_SYSLOG_DISABLE) {
        //pThis->DoTaskSysLogDisable();
    } else if (type == TASK_GLOBAL_DIR) {
        pThis->DoTaskGlobalTrustDir();
    } else if (type == TASK_GLOBAL_PROC) {
        pThis->DoTaskGlobalProc();
    };
} 

bool CEntClientNetAgent::SetClientInfoIntoConfig() {
    std::string str_soc_id;
    if (0 != SystemInfo::GetLocalInfo(SystemInfo::kLocalHardSNInfo, str_soc_id)) {
        LOG_ERROR("entclient get client soc id failed.");
        return false;
    }
    while (str_soc_id.length() > 0 && str_soc_id.length() < 32) {
        str_soc_id += str_soc_id;
    }
    str_soc_id = str_soc_id.substr(0, 32);
    CNETSTATUS->SetClientMID(str_soc_id);
    return true;
}

bool CEntClientNetAgent::Run() {
    int ret = QH_THREAD::CThread::run(NULL);
    if (ret != 0) {
        LOG_ERROR("start entclient thread error, ret = %d", ret);
        return false;
    } else {
        LOG_INFO("start entclient thread success");
        return true;
    }
}

void* CEntClientNetAgent::thread_function(void* param) {
    LOG_INFO("started the entclient thread[%ld]", (long)proc_info_utils::GetTid());
    CBackendMgr *m_backend = BACKEND_MGR;

    clock_t start_clock = 0, end_clock = 0;
    while(1) {
        //LOG_INFO("...........syslog_login_switch:%d", g_conf.syslog_login_switch);
        if (g_conf.syslog_login_switch) {
            DealSSHlogin();
        }
#if 0
        //利用这个进程来计算每秒的cpu clock的精确值，这样可以通过clock()的偏差来算时间，clock()不会引起系统调用，在调用频繁的地方很有用
        if (m_backend->cycles_per_minute == 111.0) {
            start_clock = clock(); 
            sleep(60);
            end_clock = clock();
            m_backend->cycles_per_minute = end_clock - start_clock;
        } else {
            sleep(60);
        }
#else
        sleep(60);
        ++ m_backend->minutes_count;
#endif
        // if (doWaitOrQuit(1))
        //     break;
        // sleep(60*60);
    }
    LOG_INFO("exit the entclient thread[%ld]", (long)proc_info_utils::GetTid());
    return NULL;
}


std::string CEntClientNetAgent::GetServerAddrInfo() {
    std::string strIP;
    std::string strPort;
    CNETSTATUS->GetServerIPPORT(strIP, strPort);
    return strIP + ":" + strPort;
}

bool CEntClientNetAgent::PostDataUseURL(const std::string& send_data, const char* event, std::string& recv_data) {
    std::string api = m_api_interface_[event];
    std::string url;
    CNETSTATUS->GenServerUri(api, url);
    long lHttpCode = 0;
    //LOG_INFO("net agent [post] url :%s, data[%s]\n",url.c_str(), send_data.c_str());
    bool ok = CNETSTATUS->PostDataUseURL(CPOLICYRECVMGR->get_token(), url, recv_data, (char *)send_data.c_str(), send_data.length(), lHttpCode);
    //LOG_INFO("get api[%s] HttpCode[%d] rtndata[%s] result [%s]\n", api.c_str(), int(lHttpCode), recv_data.c_str(), (ok ? "SUCCESS" : "FAILED"));
    return ok;
}

bool CEntClientNetAgent::PostDataFile(const std::string event, const std::string file, const std::string hash, std::string recv_data) {
    std::string api = m_api_interface_[event];
    std::string url;
    CNETSTATUS->GenServerUri(api, url);
    long lHttpCode = 0;
    //LOG_INFO("net agent [post] url :%s \n",url.c_str());
    bool ok = false;
    ok = CNETSTATUS->PostDataFile(CPOLICYRECVMGR->get_token(), url, recv_data, file, hash, lHttpCode); 
    //LOG_INFO("get api[%s] HttpCode[%d] rtndata[%s] result [%s]\n", api.c_str(), int(lHttpCode), recv_data.c_str(), (ok ? "SUCCESS" : "FAILED"));
    return ok;
}

bool CEntClientNetAgent::GetDataUseURL(const std::string& send_data, const char* event, std::string& recv_data) {
    std::string api = m_api_interface_[event];
    std::string url;
    CNETSTATUS->GenServerUri(api, url);
    url += "&";
    url += CPOLICYRECVMGR->get_token();
    long lHttpCode = 0;
    LOG_DEBUG("net agent [get] data[%s]",send_data.c_str());
    url += send_data;
    bool ok = CNETSTATUS->GetDataUseURL(url, recv_data, lHttpCode);
    LOG_DEBUG("get api[%s] HttpCode[%d] rtndata[%s] result [%s]", api.c_str(), int(lHttpCode), recv_data.c_str(), (ok ? "SUCCESS" : "FAILED"));
    return ok;
}

void CEntClientNetAgent::DoTaskUsbUpload() {
    std::vector<USB_INFO> vecUsb;
    std::string strJson;
    std::string str_recv = "";
    m_pUdevMonitor->get_local_all_device(vecUsb);
    build_json::Builaddperipherals(vecUsb, strJson);
    LOG_INFO("DoTaskUsbUpload　DoTaskUsbUpload.... \n");
    if (PostDataUseURL(strJson, "addperipherals",str_recv) ) {
    }

}

void CEntClientNetAgent::UploadUsbInfo(std::vector<USB_INFO> &vecUsb) {
    std::string strJson;
    std::string str_recv = "";
    m_pUdevMonitor->get_local_all_device(vecUsb);
    build_json::Builaddperipherals(vecUsb, strJson);
    LOG_INFO("UploadUsbInfo　DoTaskUsbUpload....\n");

    // std::string api = "v1/addperipherals";
    // std::string url;
    // CNETSTATUS->GenServerUri(api, url);
    // long lHttpCode = 0;
    // LOG_INFO("net agent [post] url :%s, data[%s]\n",url.c_str(), strJson.c_str());
    // bool ok = CNETSTATUS->PostDataUseURL(CPOLICYRECVMGR->get_token(), url, str_recv, (char *)strJson.c_str(), strJson.length(), lHttpCode);
    // LOG_INFO("get api[%s] HttpCode[%d] rtndata[%s] result [%s]\n", api.c_str(), int(lHttpCode), str_recv.c_str(), (ok ? "SUCCESS" : "FAILED"));
     if (PostDataUseURL(strJson, "addperipherals",str_recv) ) {
    }
}

void CEntClientNetAgent::UoloadUsbLog(std::vector<LOG_INFO> loginfo) {
    std::string str_json, response;
    build_json::BuildAlertLogJson(loginfo, str_json);
    PostDataUseURL(str_json, "upload_log", response);
}

void CEntClientNetAgent::DoTaskUsbDown() {

}

void CEntClientNetAgent::DoTaskUploadSample() {
    std::string str_recv = "";
    LOG_INFO("DoTaskUploadSample.... \n");
    if (!PostDataUseURL("", "getdraw",str_recv) ) {
        return;
    }
    std::vector<SAMPLE_INFO> lstSample;
    parse_json::ParaseSampleInfo(str_recv, lstSample);
    std::vector<SAMPLE_INFO>::iterator iter;
    for (iter = lstSample.begin(); iter != lstSample.end(); iter++) {
        if (access(iter->p_dir.c_str(), F_OK) != 0) {
            LOG_ERROR("upload process file :%s not exist", iter->p_dir.c_str());
            continue;
        } 
        std::string zip_file = iter->p_dir  + ".zip";
        const char * path = iter->p_dir.c_str();
        zip_files(zip_file.c_str(), &path, 1, "");
        if (file_utils::IsFile(zip_file) == false) {
            LOG_ERROR("upload process zip file :%s not exist", iter->p_dir.c_str());
            continue;
        } 
        if (file_utils::IsFile(zip_file) == false) {
            LOG_ERROR("upload process zip file :%s not exist", iter->p_dir.c_str());
            continue;
        }
        if (PostDataFile("uploaddraw", zip_file, iter->p_hash, str_recv) ) {
        }
        file_utils::RemoveFile(zip_file);
        LOG_INFO("Sample upload sucess :%s", zip_file.c_str());
    }
}

void CEntClientNetAgent::DoTaskgetwhiteperipherals() {
    std::string str_recv = "";

    LOG_INFO("DoTaskgetwhiteperipherals.... \n");
    if (!PostDataUseURL("", "getwhiteperipherals",str_recv) ) {
        return;
    }
    std::vector<USB_INFO> lstPolicy;
    parse_json::ParaseUSBInfoPolicy(str_recv, lstPolicy, 1);
    m_pUdevMonitor->DoSetWhite(lstPolicy);
}

void CEntClientNetAgent::DoTaskgetblackperipherals() {
    std::string str_recv = "";

    LOG_INFO("DoTaskgetblackperipherals.... \n");
    if (!PostDataUseURL("", "getblackperipherals",str_recv) ) {
        return;
    }

    std::vector<USB_INFO> lstPolicy;
    parse_json::ParaseUSBInfoPolicy(str_recv, lstPolicy, 0);
    m_pUdevMonitor->DoSetBlack(lstPolicy);
}

void CEntClientNetAgent::DoTaskUploadProcess() {
    std::string str_recv = "";
    std::string str_send = "";
    std::vector<Audit_PROCESS> processinfo;
    ProcInfo::getProcessInfos(processinfo);
    LOG_INFO("DoTaskUploadProcess.....\n");

    build_json::BuildProcessListJson(processinfo, str_send);
    if (PostDataUseURL(str_send, "upload_process",str_recv) ) {
    }
}

void CEntClientNetAgent::DoTaskUploadPDirTree() {
    std::string str_recv = "";
    std::string str_send = "";

    LOG_INFO("DoTaskUploadPDirTree.....\n");

    std::vector<FILE_INFO> dirinfo;
    FILE_INFO file_info;

    std::vector<PROTECT_DIR>::iterator iter;

    for (iter = m_vecProtectDir.begin(); iter != m_vecProtectDir.end(); iter++ ) {
        std::string dir = iter->dir;
        DirInfo::get_file_info(dir,file_info);
        dirinfo.push_back(file_info);
    }

    build_json::BuildDirInfoJson(dirinfo, str_send);
    if (PostDataUseURL(str_send, "upload_dir",str_recv) ) {
    }
}

void CEntClientNetAgent::DoTaskUploadConf() {
    std::string str_recv = "";

    LOG_INFO("DoTaskUploadConf.....\n");
    std::string str_send = "";

    CONFIG_INFO conf;
    GetConf(conf);
    build_json::BuildConfJson(conf, str_send);
    if (!PostDataUseURL(str_send, "upload_conf",str_recv) ) {
        return;
    }
}

#define  SELF_FILE  "/proc/osec/self"
static int close_self(void)
{

   	int fd = open(SELF_FILE, O_RDWR);
    if (fd < 0) {
		LOG_ERROR("open fail: %s\n", strerror(errno));  
        return -1;
    }
    std::string cmd = "veda 20231031 0";
    LOG_INFO("close self [%s],size:%d\n",cmd.c_str(), cmd.size());
    ::write(fd, cmd.c_str(), cmd.size());
    close(fd);
    return 0;
}


void CEntClientNetAgent::DoTaskUpdate() {
    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("begin DoTaskUpdate.... \n");
    POLICY_UPDATE update;
    std::string response;
     m_pBackend->DoSetSefClose();
    std::vector<LOG_INFO> loginfo;
    std::string str_json;
    LOG_INFO log;
    log.file_path = "/opt/osec/update";
    log.md5 = ""; 
    log.nType = 9001;
    log.nLevel = 3;
    log.nTime = time(NULL);

    if (!PostDataUseURL("", "update",str_recv) ) {
        log.notice_remark = "请求升级任务失败";
        loginfo.push_back(log);
        build_json::BuildAlertLogJson(loginfo, str_json);
        PostDataUseURL(str_json, "upload_log", response);
        return;
    }
    int ret1 = parse_json::ParaseUpdateJson(str_recv, update);
    if (ret1 <0) {
        LOG_ERROR("DoTaskUpdate ParaseUpdateJson error;");
        log.notice_remark = "解析升级任务json失败";
        loginfo.push_back(log);
        build_json::BuildAlertLogJson(loginfo, str_json);
        PostDataUseURL(str_json, "upload_log", response);
        return;
    }

    close_self();
    file_utils::RemoveFile("/opt/osec/.osec.txt");
    if (file_utils::IsDir("/opt/osec/update") ==  true) {
		file_utils::RemoveDirs("/opt/osec/update");
    }

    bool ret = false;
    std::string cmd = "wget --no-check-certificate -O /opt/osec/osec.zip ";
    cmd += update.downurl;
    std::string err_put;
    //ret = system_utils::SuperSystem(cmd, "update",err_put); 
    LOG_INFO("DoTaskUpdate download file cmd:%s,ret:%d", cmd.c_str(),ret);
    std::string file_name = "/opt/osec/osec.zip";

    downfile(file_name.c_str(), update.downurl.c_str());
    //down_file(update.downurl.c_str(), file_name.c_str());
    if (file_utils::IsFile(file_name) == false) {
        LOG_ERROR("DoTaskUpdate is not download file:%s", file_name.c_str());
        log.notice_remark = "升级包下载失败";
        loginfo.push_back(log);
        build_json::BuildAlertLogJson(loginfo, str_json);
        PostDataUseURL(str_json, "upload_log", response);
        return;
    }

    std::string file_md5 =  md5sum::md5file(file_name.c_str());
    if (file_md5.compare(update.hash) ) {
        LOG_ERROR("DoTaskUpdate hash not equal update md5:%s, real file md5:%s", update.hash.c_str(),
        file_md5.c_str());
        log.notice_remark = "升级任务的hash值与升级文件hash值不匹配";
        loginfo.push_back(log);
        build_json::BuildAlertLogJson(loginfo, str_json);
        PostDataUseURL(str_json, "upload_log", response);
        return;
    }

    if (file_utils::IsDir("/opt/osec/update") ==  false) {
        file_utils::MakeDirs("/opt/osec/update");
    }
    file_utils::CopyFile("/opt/osec/net_info.ini", "/var/log/net_info.ini");

    ret = ckl_unzip_file("/opt/osec/osec.zip", "/opt/osec/update");
    LOG_INFO("DoTaskUpdate ckl_unzip_file file ret:%d",ret);
    if (access("/usr/bin/dpkg", F_OK) == 0) {
        cmd = "dpkg -i /opt/osec/update/*.deb";
        err_put = "";
        ret = system_utils::SuperSystem(cmd, "update",err_put);
        LOG_INFO("DoTaskUpdate upgrade package cmd:%s,ret:%d", cmd.c_str(),ret);
    } else {
        err_put = "";
        cmd = "pkill -9 osecmonitor";
        ret = system_utils::SuperSystem(cmd, "update",err_put);
        LOG_INFO("DoTaskUpdate kill cmd:%s, ret:%d", cmd.c_str(), ret);

        cmd = "rpm -Uvh --replacefiles --force --nodeps /opt/osec/update/*.rpm";
        ret = system_utils::SuperSystem(cmd, "update",err_put);
        LOG_INFO("DoTaskUpdate upgrade package cmd:%s,ret:%d", cmd.c_str(),ret);
    }
    file_utils::CopyFile("/var/log/net_info.ini", "/opt/osec/net_info.ini");
    //file_utils::RemoveFile("/var/log/net_info.ini");
    sleep(2);
    exit(0);
    return;
}

void CEntClientNetAgent::DoTaskDownLoadProcessWhite() {
    std::string str_recv = "";

    LOG_INFO("DoTaskDownLoadProcessWhite.... \n");
    if (!PostDataUseURL("", "download_white",str_recv) ) {
        return;
    }
    m_pBackend->DoSetProcessWhite(str_recv);
    //socket_control::AsyncSendDataToOtherProcess(p_socket_client_mgr_, str_recv, OSEC_BUSINESS_NET_AGENT_NAME, OSEC_BACKEND_NAME, OSEC_REGISTER_FUNCTION_PROCESS_WHITE);
}

void CEntClientNetAgent::DoTaskDownLoadProcessBlack() {
    std::string str_recv = "";

    LOG_INFO("DoTaskDownLoadProcessBlack.... \n");
    if (!PostDataUseURL("", "download_black",str_recv) ) {
        return;
    } 
    m_pBackend->DoSetProcessBlack(str_recv);
    //socket_control::AsyncSendDataToOtherProcess(p_socket_client_mgr_, str_recv, OSEC_BUSINESS_NET_AGENT_NAME, OSEC_BACKEND_NAME, OSEC_REGISTER_FUNCTION_PROCESS_BLACK);
}

void CEntClientNetAgent::DoTaskGetConf() {
    std::string str_recv = "";
    LOG_INFO("DoTaskGetConf.... \n");
    if (!PostDataUseURL("", "getconf",str_recv) ) {
        return;
    }

    CONFIG_INFO conf;
    parse_json::ParaseConfJson(str_recv, conf);

    if (conf.serveripport.empty()) {
        LOG_ERROR("DoTaskGetConf server_ip is empty");
        return;
    }
    g_conf = conf;
    SetConf(conf);

    file_utils::CopyFile("/var/log/test.ini", "/opt/osec/test.ini");
    int hardware_switch;
    int hardware_time;

    if (conf.hardware_switch) {
        m_TimerConf.cycle_time = conf.hardware_time;
         m_TimerResource->RefreshTimer(m_TimerConf, "resupload");
    } else {
        m_TimerResource->UnRegisterEvent("resupload");
    }

    
    //m_patternRule->SetProtectDir(vecProtectDir);

    CPOLICYRECVMGR->set_sleep_time(conf.crontime);
     m_pBackend->DoSetSetConf(str_recv);
     m_pUdevMonitor->SetConf(conf);


    SYSLOG_INFO syslog_conf = {conf.api_port, conf.syslog_port, conf.syslog_process_switch, conf.proc_switch};
    m_syslog_conf = syslog_conf;
    memset(&m_addr_serv, 0, sizeof(m_addr_serv));
    m_addr_serv.sin_family = AF_INET;
    //m_addr_serv.sin_addr.s_addr = inet_addr(server_ip.c_str());
    if (!g_conf.logipport.empty()) {
        m_addr_serv.sin_addr.s_addr = inet_addr(g_conf.logipport.c_str());
    } else {
        m_addr_serv.sin_addr.s_addr = inet_addr(server_ip.c_str());
    }
    m_addr_serv.sin_port = htons(m_syslog_conf.syslog_port);
    LOG_INFO("DoTaskSysLogEnable server_ip:%s, port:%d, syslog_process_switch:%d\n", server_ip.c_str(), m_syslog_conf.syslog_port, m_syslog_conf.syslog_process_switch);
}

void CEntClientNetAgent::DoTaskDownLoadDirPoicy() {
    std::string str_recv = "";
    LOG_INFO("DoTaskDownLoadDirPoicy.... \n");
    if (!PostDataUseURL("", "getdirpolicy",str_recv) ) {
        return;
    }
    m_pBackend->DoSetDirPolicy(str_recv);
    //socket_control::AsyncSendDataToOtherProcess(p_socket_client_mgr_, str_recv, OSEC_BUSINESS_NET_AGENT_NAME, OSEC_BACKEND_NAME, OSEC_REGISTER_FUNCTION_DIR_POLICY);
}


void CEntClientNetAgent::DoTaskDownExtort() {
    std::string str_recv = "";
    LOG_INFO("DoTaskDownExtort.... \n");
    if (!PostDataUseURL("", "getprotect",str_recv) ) {
        return;
    }
     m_pBackend->DoSetExiportPolicy(str_recv);
    //socket_control::AsyncSendDataToOtherProcess(p_socket_client_mgr_, str_recv, OSEC_BUSINESS_NET_AGENT_NAME, OSEC_BACKEND_NAME, OSEC_REGISTER_FUNCTION_GET_EXIPORT);    
}

void CEntClientNetAgent::DoTaskDownProcessWhiteModule() {

    std::string str_recv = "";
    LOG_INFO("DoTaskDownProcessWhiteModule.... \n");
    if (!PostDataUseURL("", "module/white/list",str_recv) ) {
        return;
    }
    std::vector<POLICY_PROCESS_MODULE_SO> vecPolicyWhiteSo;
    parse_json::ParasePolicyProcessModule(str_recv, vecPolicyWhiteSo);
}

void CEntClientNetAgent::DoTaskDownProcessBlackModule() {

    std::string str_recv = "";
    LOG_INFO("DoTaskDownProcessBlackModule.... \n");
    if (!PostDataUseURL("", "module/black/list",str_recv) ) {
        return;
    }
    std::vector<POLICY_PROCESS_MODULE_SO> vecPolicyBlackSo;
    parse_json::ParasePolicyProcessModule(str_recv, vecPolicyBlackSo);
}

void CEntClientNetAgent::DoTaskUploadPort() {

    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("DoTaskUploadPort.... \n");
#if 0 //zebra    
    std::vector<PORT_BUSINESS_LIST> vecData;
    CPORT_MGR::GetPortBusiness(vecData);
    m_pBackend->DoSetBusPort(vecData);
    build_json::BuildBusinessPortJson(vecData, str_send);  
#else
    //m_portInfo->getNetstatinfo();
    m_portInfo->getNetstatinfoImme();
    build_json::BuildBusinessPortJson_ex(m_portInfo->netstat_web_map, str_send);  
#endif
    if (!PostDataUseURL(str_send, "upserviceport",str_recv) ) {
        return;
    }
}

void CEntClientNetAgent::DoTaskDownPortPolicy() {

    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("DoTaskDownPortPolicy.... \n");
    if (!PostDataUseURL(str_send, "getvirtualport",str_recv) ) {
        return;
    }
    std::vector<PORT_REDIRECT> vecData;
    parse_json::ParasePolicyVirtual(str_recv, vecData);
    m_pBackend->DoSetNetPortPolicy(vecData);
    // CNet_MGR mgr;
    // mgr.SetNetRedirect(vecData);
}

void CEntClientNetAgent::DoTaskUploadOpenPort() {

    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("DoTaskUploadOpenPort.... \n");
    std::vector<pOpenPort> vecData;

    build_json::BuildupOpenPortJson(vecData, str_send); 
    if (!PostDataUseURL(str_send, "upOpenPort",str_recv) ) {
        return;
    }
}

void CEntClientNetAgent::DoTaskUploadOpenPortex(std::vector<pOpenPort>& vecData) {

    std::string str_recv = "";
    std::string str_send = "";
    //LOG_INFO("DoTaskUploadOpenPort.... \n");
    build_json::BuildupOpenPortJson(vecData, str_send); 
    if (!PostDataUseURL(str_send, "upOpenPort",str_recv) ) {
        return;
    }
}

void CEntClientNetAgent::DoTaskUploadUdpDnsSyslog(const SYLOG_DNS_LOG& sys_log) {
    std::string str_send = "";
    SYLOG_DNS_LOG dns_log_tmp = sys_log;
    std::string str_recv;
    dns_log_tmp.uid = m_deviceuid;
//    LOG_INFO("DoTaskUploadUdpDnsSyslog syslog_dns_switch：%d", g_conf.syslog_dns_switch);
    if ( g_conf.syslog_dns_switch == 1) {
        build_json::BuildSysLogDnsJson(dns_log_tmp, str_send);
        CNETLOGMGR->SaveData(str_send);
    }

}

void CEntClientNetAgent::DoTaskUploadUdpNetSyslog(const SYSLOG_NET_LOG& sys_log) {
    std::string str_send = "";
    std::string str_recv;
    SYSLOG_NET_LOG net_log_tmp = sys_log;
    net_log_tmp.uid = m_deviceuid;
    int flag = 0;
//    LOG_INFO("DoTaskUploadUdpNetSyslog log_type:%d syslog_inner_switch:%d, syslog_outer_switch%d", sys_log.log_type, g_conf.syslog_inner_switch, g_conf.syslog_outer_switch);
    if ( (sys_log.log_type == 3) && (g_conf.syslog_inner_switch == 1) ) {
        flag = 1;
    } else if ( (sys_log.log_type == 2) && (g_conf.syslog_outer_switch == 1) ) {
        flag = 1;
    }
    if (flag == 1) {
        build_json::BuildSysLogNetJson(net_log_tmp, str_send);
        CNETLOGMGR->SaveData(str_send); 
    }
}

void CEntClientNetAgent::DoTaskUploadSSHSyslog(const SYLOG_SSH_LOG& sys_log) {
    std::string str_send = "";
    SYLOG_SSH_LOG net_log_tmp = sys_log;
    build_json::BuildSysLogSSHJson(net_log_tmp, str_send);
    CNETLOGMGR->SaveData(str_send);
    LOG_INFO("ssh data save ip:%s, username:%s, time:%d, result:%d", sys_log.ip.c_str(), sys_log.username.c_str(), sys_log.time, sys_log.status);
}

void CEntClientNetAgent::DoTaskUploadUdpEdrProcessSyslog(const EDRPROCESS_LOG& sys_log) {
    std::string str_send = "";
    std::string str_recv;
    EDRPROCESS_LOG dns_log_tmp = sys_log;   
    dns_log_tmp.uid = m_deviceuid;
    //LOG_INFO("1111111111post log.............syslog_process_switch:%d", g_conf.syslog_process_switch);
    if ( g_conf.syslog_process_switch == 1) {
        build_json::BuildProcessEDRJson(dns_log_tmp, str_send);
        CNETLOGMGR->SaveData(str_send);
    }
}

void CEntClientNetAgent::DoUploadHttpSyslog(const std::string &syslog) {
    std::string str_recv;
    if (!PostDataUseURL(syslog, "putsyslog",str_recv) ) {
        LOG_DEBUG("DoUploadSyslog");
    }
}

void CEntClientNetAgent::udpSend(const std::string& str_data) {

    int len = sizeof(m_addr_serv);
    int send_num = 0;
    send_num = sendto(m_socketUdpFd, str_data.c_str(), str_data.length(), 0, (struct sockaddr *)&m_addr_serv, len);
    if(send_num < 0) {
        LOG_ERROR("sendto error data:%s, error:%d", str_data.c_str(), errno);
    } else {
        LOG_DEBUG("sendto sucess data:%s", str_data.c_str());
    }
}

void CEntClientNetAgent::DoTaskgetPlugging() {

    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("DoTaskgetPlugging.... \n");
    if (!PostDataUseURL(str_send, "getPlugging",str_recv) ) {
        return;
    }
    std::vector<NETBLOCK> vecData;
    parse_json::ParaseNetBlockList(str_recv, vecData);
    CNet_MGR mgr;
    mgr.SetNetBlockList(vecData);
    std::vector<FirewallRule> lstFireWall;
    mgr.GetNetPolicy(lstFireWall);
    //if (!lstFireWall.empty()) 
    {
        m_pBackend->DosetNetBlockPolicy(lstFireWall);
    }
}


void CEntClientNetAgent::DoTaskgetipwhitelist() {

    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("DoTaskgetipwhitelist.... \n");
    if (!PostDataUseURL(str_send, "getipwhitelist",str_recv) ) {
        return;
    }
    std::vector<NET_PROTECT_IP> vecData;
    parse_json::ParaseNetWhiteBlack(str_recv, vecData, 2);
    {
        m_pBackend->DosetWhiltePolicy(vecData);
    }
    // CNet_MGR mgr;
    // mgr.SetNetWhitePolicy(vecData);
}

void CEntClientNetAgent::DoTaskgetipblacklist() {

    std::string str_recv = "";
    LOG_INFO("DoTaskgetipblacklist.... \n");
    if (!PostDataUseURL("", "getipblacklist",str_recv) ) {
        return;
    }
    std::vector<NET_PROTECT_IP> vecData;
    parse_json::ParaseNetWhiteBlack(str_recv, vecData, 1);
    CNet_MGR mgr;
    mgr.SetNetBlackPolicy(vecData);
    std::vector<FirewallRule> lstFireWall;
    mgr.GetNetPolicy(lstFireWall);
    //if (!lstFireWall.empty()) 
    {
        m_pBackend->DosetNetBlockPolicy(lstFireWall);
    }
}

#if 0
void CEntClientNetAgent::DoTaskSysLogEnable() {
    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("DoTaskSysLogEnable.... \n");
    if (!PostDataUseURL(str_send, "getSyslogConf",str_recv) ) {
        return;
    }
    SYSLOG_INFO syslog_conf;
    parse_json::ParaseSysLogConfJson(str_recv, syslog_conf);
    m_syslog_conf = syslog_conf;
    memset(&m_addr_serv, 0, sizeof(m_addr_serv));
    m_addr_serv.sin_family = AF_INET;
    m_addr_serv.sin_addr.s_addr = inet_addr(server_ip.c_str());
    m_addr_serv.sin_port = htons(m_syslog_conf.syslog_port);
    LOG_INFO("DoTaskSysLogEnable server_ip:%s, port:%d", server_ip.c_str(), m_syslog_conf.syslog_port);
    m_pBackend->DosetNetSyslogConf(m_syslog_conf);

}

void CEntClientNetAgent::DoTaskSysLogDisable() {
    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("DoTaskSysLogDisable.... \n");
    if (!PostDataUseURL(str_send, "getSyslogConf",str_recv) ) {
        return;
    }
    SYSLOG_INFO syslog_conf;
    parse_json::ParaseSysLogConfJson(str_recv, syslog_conf);
    m_syslog_conf = syslog_conf;
    memset(&m_addr_serv, 0, sizeof(m_addr_serv));
    m_addr_serv.sin_family = AF_INET;
    m_addr_serv.sin_addr.s_addr = inet_addr(server_ip.c_str());
    m_addr_serv.sin_port = htons(m_syslog_conf.syslog_port);
    m_pBackend->DosetNetSyslogConf(m_syslog_conf);
}

#endif

void CEntClientNetAgent::DoTaskGlobalTrustDir() {
    std::string str_recv = "";
    std::string str_send = "";
    LOG_INFO("gettrustdir.... \n");
    if (!PostDataUseURL(str_send, "gettrustdir",str_recv) ) {
        return;
    }
    std::vector<GlobalTrusrDir> global_trustdir;
    parse_json::ParaseGettrustdirJson(str_recv, global_trustdir);
    m_pBackend->DosetGlobalTrustDir(global_trustdir);
}

static int linux_proc_task_flag = 0; 
const char* dir_name[] = { "/bin/",
                        "/usr/bin/",
                        "/usr/sbin/",
                        "/usr/local/bin/",
                         NULL };

static int getfilenamebydir(void* param, std::string path)
{
    std::string str_recv = "";
    std::string str_send = "";
    std::vector<LinuxDirProc> vecInfo;
    CEntClientNetAgent* pAgent = (CEntClientNetAgent*)param;
    std::string currPath=path;   
    DIR* dp = opendir(path.c_str());
    if(dp == NULL)
    {
        LOG_ERROR("Open directory error :%s", path.c_str());
        return -1;
    }
    
    struct dirent *entry = NULL;
    while((entry = readdir(dp)))
    {               
        if(entry->d_name[0]=='.'||strcmp(entry->d_name,"..")==0)
        {
            continue;
        }

        struct stat statbuf;
        std::string path_file = currPath + entry->d_name;
        lstat(path_file.c_str(), &statbuf);
        if(S_ISDIR(statbuf.st_mode)) {
                continue;
        } else {
            LOG_DEBUG("get one file:%s", path_file.c_str());
            LinuxDirProc  linuxProc;
            linuxProc.dir = path_file;
            linuxProc.hash = md5sum::md5file(path_file.c_str());
            linuxProc.introduce = "linux";
            linuxProc.copyright = "linux_gnu";
            vecInfo.push_back(linuxProc);
            if (vecInfo.size() >=200) {
                build_json::BuildLinuxDirProcessJson(vecInfo, str_send);
                if (pAgent) {
                    pAgent->PostDataUseURL(str_send, "upload/suffix/exe",str_recv);
                }
                vecInfo.clear();
                sleep(5);
            } 
        }   
    }
    closedir(dp);
    return 0;
}

static void* LinuxProcThread(void* param) {
    std::vector<LinuxDirProc> vecInfo;
    int i = 0;
    CEntClientNetAgent* pAgent = (CEntClientNetAgent*)param;
    if (pAgent == NULL) {
        LOG_ERROR("pAgent is NULL");
        return NULL;
    }

    while ( dir_name[i] != NULL)
    {
       getfilenamebydir(param, dir_name[i]);
        i++;
    }
    linux_proc_task_flag = 0;
    pAgent->CloseTask(TASK_GLOBAL_PROC);
    return NULL;
}

void CEntClientNetAgent::DoTaskGlobalProc() {
    pthread_t tid;
    LOG_INFO("DoTaskGlobalProc.... \n");
    if (linux_proc_task_flag > 0) {
        return;
    }
    int err = pthread_create(&tid, NULL, LinuxProcThread,(void*)this);
    if(err!=0) {
        LOG_ERROR("pthread_create error \n");
    } else {
        linux_proc_task_flag = 1;
    }
}

#include<fcntl.h>
void CEntClientNetAgent::DoTaskUninstall() {

    // std::string file_path = "/opt/osec/passwd.txt";
    // FILE *fd_osec = fopen(file_path.c_str(), "a+");
    // if (fd_osec) {
    //     fclose(fd_osec);
    // }
    LOG_INFO("uninstall package osec");
    printf("uninstall package osec\n");
    std::string str_recv = "";
    if (!PostDataUseURL("", "uninstall",str_recv) ) {
        return;
    }
     m_pBackend->DoSetSefClose();
    if (file_utils::IsExist("/var/log/net_info.ini")) {
        file_utils::RemoveFile("/var/log/net_info.ini");
    }
    
    if (file_utils::IsExist("/opt/osec/update")) {
        file_utils::RemoveDirs("/opt/osec/update");
    }

    if (file_utils::IsExist("/opt/osec/log")) {
        file_utils::RemoveDirs("/opt/osec/log");
    }

    if (file_utils::IsExist("/opt/osec/Log")) {
        file_utils::RemoveDirs("/opt/osec/Log");
    }

    close_self();

    std::string cmd_string = " systemctl disable osec";
    std::string err_put = "";
    LOG_INFO("DoTaskUninstall disable osec service cmd:%s", cmd_string.c_str());
    int ret = system_utils::SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall disable osec service cmd:%s, ret:%d", cmd_string.c_str(), ret);

    cmd_string = " systemctl stop osec";
    err_put = "";
    LOG_INFO("DoTaskUninstall disable osec service cmd:%s", cmd_string.c_str());
    ret = system_utils::SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall disable osec service cmd:%s, ret:%d", cmd_string.c_str(), ret);


    err_put = "";
    cmd_string = "pkill -9 osecmonitor";
    ret = system_utils::SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall kill cmd:%s, ret:%d", cmd_string.c_str(), ret);

    //file_utils::RemoveDirs("/opt/osec/.osec.txt");
    file_utils::RemoveFile("/opt/osec/.osec.txt");
    cmd_string = "dpkg -P osec";
    err_put = "";
    LOG_INFO("DoTaskUninstall dpkg cmd:%s", cmd_string.c_str());
    ret = system_utils::SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall dpkg cmd:%s, ret:%d", cmd_string.c_str(), ret);
    cmd_string = "rpm -qa |grep osec |xargs -I {} rpm -e {}";
    err_put = "";
    LOG_INFO("DoTaskUninstall rpm cmd:%s", cmd_string.c_str());
    ret = system_utils::SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall rpm cmd:%s, ret:%d", cmd_string.c_str(), ret);
    file_utils::RemoveDirs("/opt/osec");
    cmd_string = "pkill -10 MagicArmor_1";
    ret = system_utils::SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall kill cmd:%s, ret:%d", cmd_string.c_str(), ret);
    cmd_string = "pkill -9 MagicArmor_0";
    err_put = "";
    LOG_INFO("DoTaskUninstall stop osec service cmd:%s", cmd_string.c_str());
    ret = system_utils::SuperSystem(cmd_string, "uninstall",err_put);
    LOG_INFO("DoTaskUninstall stop osec service cmd:%s, ret:%d", cmd_string.c_str(), ret);

    exit(1);
}

void CEntClientNetAgent::DoTaskDownProcessModule() {

    std::string str_recv = "";
    LOG_INFO("DoTaskDownProcessModule.... \n");
    if (!PostDataUseURL("", "module/process",str_recv) ) {
        return;
    }
    std::vector<POLICY_SINGLE_PROCESS_SO> vecSingleSo;
    parse_json::ParaseSingleProcessModule(str_recv, vecSingleSo);
    std::vector<POLICY_SINGLE_PROCESS_SO>::iterator iter;
    std::vector<Audit_PROCESS> vecProcess;
    for (iter = vecSingleSo.begin(); iter !=  vecSingleSo.end(); iter++) {
        Audit_PROCESS vecSoPath;
        ProcInfo::getProcAndDepends(iter->pid, vecSoPath);
        vecSoPath.hash = iter->hash;
        vecProcess.push_back(vecSoPath);
    }
    std::string str_module_json = "";
    build_json::BuildProcessListJson(vecProcess,str_module_json);
    //获取指定Pid的模块信息
    if (!PostDataUseURL(str_module_json, "upload/proc/module",str_recv) ) {
        return;
    }
}

void CEntClientNetAgent::DoTaskDownAllProcessModule() {

    std::string str_module_json = "";
    std::string str_recv = "";
     LOG_DEBUG("DoTaskDownAllProcessModule.... \n");
     std::vector<Audit_PROCESS> vecProcess;
     ProcInfo::getProcessInfosModule(vecProcess);
    build_json::BuildProcessListJson(vecProcess, str_module_json, 0);
    if (!PostDataUseURL(str_module_json, "upload/allproc/module",str_recv) ) {
        return;
    }
    str_module_json = "";
    build_json::BuildCloseTask(22, str_module_json);
    if (!PostDataUseURL(str_module_json, "closetask", str_recv) ) {
        return;
    }
}

void CEntClientNetAgent::CloseTask(int taskid) {
    std::string str_module_json = "";
    std::string str_recv = "";
    build_json::BuildCloseTask(taskid, str_module_json);
    if (!PostDataUseURL(str_module_json, "closetask", str_recv) ) {
        return;
    }
}

void CEntClientNetAgent::DoUploadClientLog(const std::string &recvData) {
    std::string strUploadClientLog = recvData;
    //LOG_INFO("DoUploadClientLog recv_content=%s", strUploadClientLog.c_str());
    std::string response("-1");
    if (false == PostDataUseURL(strUploadClientLog, "upload_log", response)) {
        LOG_ERROR("do upload client log post request failed.");
        return;
    }
    //socket_control::ResponseCallFunc(p_socket_client_mgr_, response, recvData);
}

void CEntClientNetAgent::DoUploadProcStart(const std::string &recvData) {
    std::string strUpload = recvData;
    LOG_DEBUG("DoUploadProcStart autouploadprocess recv_content=%s", strUpload.c_str());
    std::string str_recv = "";
    if (PostDataUseURL(strUpload, "autouploadprocess",str_recv) ) {
    }
    // if (PostDataUseURL(strUpload, "upload_process",str_recv) ) {
    // }
}

void CEntClientNetAgent::DoUploadSelfProtectLog(const std::string &recvData) {
    std::string strUpload = recvData;
    std::string  response;
    PostDataUseURL(strUpload, "upload_log", response);
}
void CEntClientNetAgent::DoUploadSyslog(const std::string &recvData) {
    std::string strUpload = recvData;
    std::string recv_data;
    LOG_DEBUG("DoUploadSyslog recv_content=%s", strUpload.c_str());
    std::string str_recv = "";
    std::string ip, port;
    CNETSTATUS->GetServerIPPORT(ip, port);
    std::string api = ip + ":";
    api += string_utils::ToString(m_syslog_conf.syslog_port);
    std::string url;
    CNETSTATUS->GenServerUri(api, url);
    long lHttpCode = 0;
    //LOG_INFO("net agent [post] url :%s, data[%s]\n",url.c_str(), strUpload.c_str());
    bool ok = CNETSTATUS->PostDataUseURL(CPOLICYRECVMGR->get_token(), url, recv_data, (char *)strUpload.c_str(), strUpload.length(), lHttpCode);
    //LOG_INFO("get api[%s] HttpCode[%d] rtndata[%s] result [%s]\n", api.c_str(), int(lHttpCode), recv_data.c_str(), (ok ? "SUCCESS" : "FAILED"));
}

void CEntClientNetAgent::DoScanDir() {

    std::string str_recv = "";
    std::string str_send = "";

    LOG_DEBUG("DoScanDir.... \n");
    if (!PostDataUseURL("", "getdirinfo",str_recv) ) {
        return;
    }

    std::vector<FILE_INFO> dirinfo;

    std::vector<DIR_VIEW> vecDirView;
    parse_json::ParaseDirView(str_recv,vecDirView);
    std::vector<DIR_VIEW>::iterator iter;

    for (iter = vecDirView.begin(); iter != vecDirView.end(); iter++ ) {
        std::string dir = iter->dir;
        std::vector<std::string> vecDirFile;
        vecDirFile = CBrowseDirLinux::GetDirFilenames(dir.c_str(), false);
        std::vector<std::string>::iterator sub_iter;
        for (sub_iter = vecDirFile.begin(); sub_iter != vecDirFile.end(); sub_iter++) {
            
            FILE_INFO file_info;
            DirInfo::get_file_info(*sub_iter,file_info);
            file_info.id = iter->id;
            dirinfo.push_back(file_info);
        }
    }

    build_json::BuildDirInfoJson(dirinfo, str_send);
    if (!PostDataUseURL(str_send, "upload_dir",str_recv) ) {
        return;
    }
 }
bool CEntClientNetAgent::DoUnInstall() {
    return true;
}

void CEntClientNetAgent::GetConf(CONFIG_INFO &conf) {
    std::string net_info_path = PathManager::GetClientServerNetInfoPath();
    if (!file_utils::IsExist(net_info_path)) {
        LOG_ERROR("local socket config file[%s] is not exist.", net_info_path.c_str());
    }
    INIParser parser;
    if(!parser.ReadINI(net_info_path)) {
        LOG_ERROR("GenServerUri:parse net info path[%s] failed.", net_info_path.c_str());
    } else {
        conf.serveripport = parser.GetValue(SECTION_SERVERINFO, KEY_serveripport);
        conf.logipport = parser.GetValue(SECTION_SERVERINFO, KEY_logipport);
        conf.logproto = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_logproto).c_str());

        conf.logsent = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_logsent).c_str());
        conf.proc_protect = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_proc_protect).c_str());
        conf.file_protect = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_file_protect).c_str());

        conf.crontime = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_comtime).c_str());
        conf.extortion_protect = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_extortion).c_str());

        conf.proc_switch = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_proc_switch).c_str());
        conf.module_switch = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_module_switch).c_str());
        conf.file_switch = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_file_switch).c_str());

        conf.open_port_switch = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_open_port_switch).c_str());
        conf.usb_switch = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_usb_switch).c_str());
        conf.extortion_switch = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_extortion_switch).c_str());
        conf.usb_protect = atoi(parser.GetValue(SECTION_SERVERINFO, KEY_usb_protect).c_str());

    }

}
void CEntClientNetAgent::SetConf(const CONFIG_INFO &conf) {
    INIParser parser;
    std::string net_info_path = PathManager::GetClientServerNetInfoPath();
    if (!parser.ReadINI(net_info_path)) {
        LOG_INFO("parse net info path[%s] failed.", net_info_path.c_str());
        return;
    }
    //parser.SetValue(SECTION_SERVERINFO, KEY_serveripport, conf.serveripport);
    parser.SetValue(SECTION_SERVERINFO, KEY_logipport, conf.logipport);

    std::string value = string_utils::ToString(conf.logproto);
    parser.SetValue(SECTION_SERVERINFO, KEY_logproto, value);
    value = string_utils::ToString(conf.logsent);
    parser.SetValue(SECTION_SERVERINFO, KEY_logsent,value);
     value = string_utils::ToString(conf.proc_protect);
    parser.SetValue(SECTION_SERVERINFO, KEY_proc_protect, value);
     value = string_utils::ToString(conf.file_protect);
    parser.SetValue(SECTION_SERVERINFO, KEY_file_protect, value);
     value = string_utils::ToString(conf.crontime);
    parser.SetValue(SECTION_SERVERINFO, KEY_comtime, value);
     value = string_utils::ToString(conf.extortion_protect);
    parser.SetValue(SECTION_SERVERINFO, KEY_extortion, value);

     value = string_utils::ToString(conf.proc_switch);
    parser.SetValue(SECTION_SERVERINFO, KEY_proc_switch, value);

    value = string_utils::ToString(conf.module_switch);
    parser.SetValue(SECTION_SERVERINFO, KEY_module_switch, value);

    value = string_utils::ToString(conf.file_switch);
    parser.SetValue(SECTION_SERVERINFO, KEY_file_switch, value);

    value = string_utils::ToString(conf.open_port_switch);
    parser.SetValue(SECTION_SERVERINFO, KEY_open_port_switch, value);
    value = string_utils::ToString(conf.usb_switch);
    parser.SetValue(SECTION_SERVERINFO, KEY_usb_switch, value);
    value = string_utils::ToString(conf.extortion_switch);
    parser.SetValue(SECTION_SERVERINFO, KEY_extortion_switch, value);
    value = string_utils::ToString(conf.usb_protect);
    parser.SetValue(SECTION_SERVERINFO, KEY_usb_protect, value);

    parser.WriteINI(net_info_path);

    std::string strIP = "";
    std::string strPort = "";
    if (conf.serveripport.find(":") == std::string::npos) {
        strIP = conf.serveripport;
        strPort = "";
    } else {
        std::string strIP = conf.serveripport.substr(0,conf.serveripport.find_last_of(":"));
        std::string strPort = conf.serveripport.substr(conf.serveripport.find_last_of(":")+1); 
    }
    if (isValidNetInfo("/opt/osec/net_info.ini") == 0) {
        LOG_INFO("cp /opt/osec/net_info.ini /var/log/ \n");
        file_utils::CopyFile("/var/log/net_info.ini", "/opt/osec/net_info.ini");
    } else {
        file_utils::CopyFile("/opt/osec/net_info.ini", "/var/log/net_info.ini");
    }
    //CNETSTATUS->RefreshServerIpPort(strIP, strPort);
}

