#ifndef _KERNEL_EVENT_HANDLER_H
#define _KERNEL_EVENT_HANDLER_H

#include "common/pcinfo/pc_base_info.h"
#include "common/qh_thread/thread.h"
#include "common/md5sum.h"
#include <map>
#include <list>
#include <string>
#include <set>
#include "osec_common/global_message.h"
#include "common/kernel/gnHead.h"
#include "net_agent/zcopy_mgr.h"
#include "common/timer/timer_interface.hpp"
#include "common/timer/timer.h"

//#include "backend/net_agent/net_mgr/netstate.h"
class CPortInfo;

using namespace std;


/*
######告警类型数据
```blade
--------进程告警---------
监控模式 1001-1099  【传递结果，不处理过程】
1001:不明进程启动告警
1002:黑名单启动告警
保护模式 1101-1199
1101:不明进程启动阻止告警
1102:黑名单进程启动阻止告警
1103:不明进程终止告警
1104:黑名单进程终止告警

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
--------agent 告警类型---------
基本告警 9001-9999
9001:升级错误
9002:agent被破坏告警

*/




class IKernelConnector;
class CNetReportMgr;
class CEntClientNetAgent;
class ProcessMd5Mgr;
class CTimer;
#define PROCEEE_WHITE_TYPE 1
#define PROCEEE_BLACK_TYPE 2

class KernelEventHandler
{
private:
    typedef std::set<std::string> CStringSet;
    typedef std::map<std::string,void*> CStringMap;
public:

    static KernelEventHandler* GetEventHandler();
    //only register one time
    int RegReportHandler();
    int UnRegReportHandler();
    int EndBoolWaiting(void* pwait_flag, int bContinue);
    int EndWaiting(void* pwait_flag);
    int AuditProcessOper(const struct av_process_info* unlink_info, const std::string &hash, const int &level, const std::string &param = "", const std::string &pparam ="");
    int AuditFileOper(const struct av_file_info* unlink_info, const int &level, const std::string &hash, const int &pos = 0);
public:
    bool SetSelfProtected(int status);
    bool SetSelfEnable(int status);
    bool SetNetSyslogPolicy(const SYSLOG_INFO& syslog_conf_data);
    bool AddWhiteProcess(const std::string &filePath);
    bool SetKernelAction(struct defense_action *action);
    void addWhiteExes(void);
    bool SetNetPortKernelPolicy(const std::vector<PORT_REDIRECT> &vecData, struct NetworkKernelPolicyInfo& infoPolicy);
    bool SetNetBlock(const std::vector<FirewallRule>& lstFireWall, struct NetworkKernelPolicyInfo& infoPolicy);
    void SettWhilteIpPolicy(std::vector<NET_PROTECT_IP> vecData);
    void SetExiportDir(std::vector<POLICY_EXIPOR_PROTECT> &g_VecExiportInfo);
    int Process_match_handle(struct av_process_info &procinfo ,std::string &hash_info, int& level_info);

public:
    void SetPlicyConf(const CONFIG_INFO &conf );
    void SetPolicyExiport(std::vector<POLICY_EXIPOR_PROTECT> &vecInfo);
    void SetPolicyDir(std::vector<POLICY_PROTECT_DIR> &vecProtectDir);
    void SetPolicyProcess(std::map<std::string, std::string> &mapProcessInfo, const int &type);
    void SetFlags(const int &file_flag, const int &process_flag, const int &explore_flag);
    void SetFlags_ex(const int &file_flag, 
                                    const int &process_flag, 
                                    const int &explore_flag, 
                                    const int &file_mode, 
                                    const int &process_mode, 
                                    const int &explore_mode, 
                                    const int &syslog_inner_switch, 
                                    const int &syslog_outer_switch, 
                                    const int &syslog_dns_switch
                                    );  
    void SetSockMgr(CEntClientNetAgent *pSockNetAgent);
	int Init();
    void KillBlackProcess(const std::string &hash, const std::string &file_value);

    int AuditOpenPortOper(std::vector<pOpenPort> &);

	KernelEventHandler();
	~KernelEventHandler();
private:
    void SocatTransfer();
    bool SetbusinessPort(const uint16_t *ports, const int data_len);
    int UpdateBusinessPortEvent(); 
public:
    CEntClientNetAgent* m_pSockNetAgent;
private:
    CNetReportMgr *m_pReport;
    CPortInfo *m_portinfo;
    IKernelConnector* kernel_connector;
    void* handle;
    //ProcessMd5Mgr *m_processMd5Mgr;
    //clock_t baseCPUTimestamp;
    long baseSystemTime;
    CTimer *m_TimerBusinessPort;
    TimerHandlerConf m_TimerConf;

};

#define OSEC_KERNEL_HANDLE (KernelEventHandler::GetEventHandler())

#endif
