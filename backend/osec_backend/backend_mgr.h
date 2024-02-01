#ifndef CBackendMgr_H
#define CBackendMgr_H

#include "common/socket_client/ISocketClientMgr.h"
#include "osec_common/global_message.h"
#include <string>
#include <set>
#include <ctime>

using namespace std;

class KernelEventHandler;
class CEntClientNetAgent;
class CPortInfo; 
class ConnBlock_MGR;
class PatternRules_MGR;

class CBackendMgr
{
private:
    CBackendMgr();

public:
    static CBackendMgr *getInstance();
    bool init();
    bool uninit();
    void setLabelUserDeviceInfo();
public:
    int InitKernel(CEntClientNetAgent* pAgent);
    void DoSetProcessWhite(const std::string &recvData);
    void DoSetProcessBlack(const std::string &recvData);
    void DoSetSetConf(const std::string &recvData);
    //void DoSetSetConfExt(const std::string &recvData);
    void DoSetDirPolicy(const std::string &recvData);
    void DoSetExiportPolicy(const std::string &recvData);
    void DoSetNetPortPolicy(std::vector<PORT_REDIRECT> &vecData);
    void DosetNetSyslogConf(const SYSLOG_INFO& syslog_conf_data);
    void SetDriverDefaultPolicy();
    void GetConf(CONFIG_INFO &conf);
    void DosetNetBlockPolicy(std::vector<FirewallRule> lstFireWall);
    void DoSetBusPort(std::vector<PORT_BUSINESS_LIST> vecData);
    void DosetWhiltePolicy(std::vector<NET_PROTECT_IP> vecData);
    void DoSetSefClose();
    void DosetGlobalTrustDir(std::vector<GlobalTrusrDir> global_trustdir);
private:
    bool m_bInit;
    KernelEventHandler* keh;
    static CBackendMgr *m_pInstance;
    CEntClientNetAgent *m_pNetAgent;
    CPortInfo   *m_portInfo; 
    ConnBlock_MGR *m_connBlock;
    PatternRules_MGR *m_patternRule;
public:
    clock_t cycles_per_minute;
    uint64_t minutes_count;
};

#define BACKEND_MGR CBackendMgr::getInstance()

#endif
