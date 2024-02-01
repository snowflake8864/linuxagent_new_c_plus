#ifndef BACKEND_NET_AGENT_ENT_CLIENT_NET_AGENT_H_
#define BACKEND_NET_AGENT_ENT_CLIENT_NET_AGENT_H_

#include <map>
#include "common/socket_client/ISocketClientMgr.h"
#include "common/singleton.hpp"
#include "common/qh_thread/thread.h"
#include "osec_common/global_message.h"
#include "system_login.h"
#include "backend/net_agent/net_mgr/netstate.h"
#include "common/timer/timer_interface.hpp"

class CBackendMgr;
class CUdiskMonitorMgr;
class CTimer;
class CEntClientNetAgent: public QH_THREAD::CThread {
  public:
    CEntClientNetAgent()
        : m_inited_(false)
        , m_login_status_(false) {
    }
    ~CEntClientNetAgent();

  public:
    bool Init(CBackendMgr *pBackend);
    bool UnInit();
    bool Run();

  public:
    bool DoUnInstall();

  public:
    bool InitInterface();
    bool InitEntClient();
    static void RunTaskCallBack(void* pParam, TASK_TYPE type);
    void UploadUsbInfo(std::vector<USB_INFO> &vecUsb);
    void DoTaskUploadOpenPortex(std::vector<pOpenPort>& vecData);
    void UoloadUsbLog(std::vector<LOG_INFO> loginfo);
  protected:
    virtual void* thread_function(void* param);
    int ResourceEvent();

  public:
    void DoUploadClientLog(const std::string &recvData);
    void DoUploadHttpSyslog(const std::string &syslog);
    void DoSetOnlineStatus(const bool nOnline);
    void DealSSHlogin();
    void DoTaskUploadSSHSyslog(const SYLOG_SSH_LOG& sys_log);
  private:
    void DoTaskUploadProcess();
    void DoTaskUploadPDirTree();
    void DoTaskUploadConf();
    void DoTaskDownLoadProcessWhite();
    void DoTaskGetConf();
    void DoTaskDownLoadDirPoicy();
    void DoTaskUpdate();
    void DoScanDir();
    void DoTaskDownLoadProcessBlack();
    void DoTaskDownExtort();
    void DoTaskDownProcessModule();
    void DoTaskDownAllProcessModule();
    void DoTaskDownProcessWhiteModule();
    void DoTaskDownProcessBlackModule();
    void DoTaskUninstall();
    void DoTaskUploadPort();
    void DoTaskDownPortPolicy();
    void DoTaskUploadOpenPort();
    void DoTaskgetPlugging();
    void DoTaskgetipwhitelist();
    void DoTaskgetipblacklist();
    void DoTaskgetwhiteperipherals();
    void DoTaskgetblackperipherals();
    void DoTaskUsbUpload();
    void DoTaskUsbDown();
    void DoTaskUploadSample();
    void DoTaskSysLogEnable();
    void DoTaskSysLogDisable();
    void DoTaskGlobalTrustDir();
    void DoTaskGlobalProc();
  public:
    void DoUploadProcStart(const std::string &recvData) ;
    std::string GetServerAddrInfo();
    void DoUploadSyslog(const std::string &recvData);
    void DoUploadSelfProtectLog(const std::string &recvData);
    void DoTaskUploadUdpDnsSyslog(const SYLOG_DNS_LOG& sys_log);
    void DoTaskUploadUdpNetSyslog(const SYSLOG_NET_LOG& sys_log);
    void DoTaskUploadUdpEdrProcessSyslog(const EDRPROCESS_LOG& sys_log);
    void udpSend(const std::string& str_data);
    bool PostDataUseURL(const std::string& send_data, const char* event, std::string& recv_data);
    void CloseTask(int taskid);
  private:
    bool PostDataFile(const std::string event, const std::string file, const std::string hash, std::string recv_data);
    bool GetDataUseURL(const std::string& send_data, const char* event, std::string& recv_data);
    std::string GetOperEvent(const char* lpFunction);
    bool SetClientInfoIntoConfig();

    void GetConf(CONFIG_INFO &conf);
    void SetConf(const CONFIG_INFO &conf);

  private:
    QH_THREAD::CMutex m_mutex_file;
    volatile bool m_inited_;
    volatile bool m_login_status_;
    //std::map<std::string, std::string> m_api_interface_;
    std::vector<PROTECT_DIR> m_vecProtectDir;
    CBackendMgr *m_pBackend;
    CUdiskMonitorMgr *m_pUdevMonitor;
    SYSLOG_INFO m_syslog_conf;
    CPortInfo *m_portInfo;
    CTimer *m_TimerResource;
    TimerHandlerConf m_TimerConf;
  private:
    int m_socketUdpFd;
    struct sockaddr_in m_addr_serv;
  public:
    std::string m_deviceuid;
    std::string server_ip;
    bool m_bOnlineClient;
    std::vector<UTMP_INFO_T> m_CurrentVecUbmp;
    std::vector<UTMP_INFO_T> m_CurrentVecWtmp;
};

#endif /* BACKEND_NET_AGENT_ENT_CLIENT_NET_AGENT_H_ */

