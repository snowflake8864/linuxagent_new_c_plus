
#include "backend_mgr.h"
#include "common/log/log.h"
#include "common/uuid.h"
#include "common/utils/file_utils.h"
#include "common/utils/proc_info_utils.h"
#include "common/singleton.hpp"
#include "common/ini_parser.h"
#include "common/pcinfo/system_info.h"
#include "common/ASFramework/ASBundleImpl.hpp"
#include "common/socket/socket_process_info.h"
#include "common/socket/socket_utils.h"
#include "osec_common/global_config.hpp"
#include "osec_common/osec_pathmanager.h"
#include "osec_common/socket_osec.h"
#include "osec_common/osec_socket_utils.h" 
#include "kernel_event_handler.h"
#include "backend/net_agent/data_operation/parse_json.h"
#include "backend/net_agent/data_operation/build_json.h"
#include "backend/net_agent/ent_client_net_agent.h"
#include "backend/net_agent/policy_recv.h"
#include <arpa/inet.h>
#include "backend/net_agent/net_mgr/netstate.h"
#include "backend/net_agent/conn_block_mgr.h"
#include "backend/net_agent/pattern_rules_mgr.h"
#define COMMUNICATION_BACKEND_SERVICE "backend_service"


CBackendMgr *CBackendMgr::m_pInstance = NULL;
static std::vector<PORT_BUSINESS_LIST> g_BuspotList;
CBackendMgr::CBackendMgr()
{
    m_bInit = false;
    g_BuspotList.clear();
    cycles_per_minute = 111.0;
    minutes_count = 0;
}

CBackendMgr *CBackendMgr::getInstance()
{
    if (m_pInstance == NULL) {
        m_pInstance = new CBackendMgr();
    }
    return m_pInstance;
}

bool CBackendMgr::init()
{
    if (m_bInit) {
        return true;
    }
    m_bInit = true;
    bool bRet = false;

    m_pNetAgent = new CEntClientNetAgent();
    if (m_pNetAgent) {
        m_pNetAgent->Init(this);
    }
    //m_portInfo = CPORTINFO;
    m_portInfo = new CPortInfo();
    if (InitKernel(m_pNetAgent)) {

        return false;
    }
    if (keh) {
        keh->SetSockMgr(m_pNetAgent);
    }

    if (file_utils::IsExist("/opt/osec/osec.zip")) {
        file_utils::RemoveFile("/opt/osec/osec.zip");
    }
    int try_cnt = 0;
    while(!file_utils::IsExist("/proc/osec/dpi/file_patterns")) {
        sleep(1);   
        LOG_INFO("=============FILE_PATTERNS_PROC_FILE is no exist...\n");
        if (++try_cnt >= 5) {
            break;
        }
    }
    m_patternRule = &Singleton<PatternRules_MGR>::Instance();
    m_patternRule->Init();
    m_connBlock = &Singleton<ConnBlock_MGR>::Instance();
    LOG_INFO("finis init pattern Rules.....\n");
    return bRet;
}

bool CBackendMgr::uninit()
{
    if (m_pNetAgent) {
        m_pNetAgent->UnInit();
        delete m_pNetAgent;
    }
    if (m_patternRule) {
        m_patternRule->UnInit();
        delete m_patternRule;
    }
    return true;
}

int CBackendMgr::InitKernel(CEntClientNetAgent* pAgent)
{
    keh = KernelEventHandler::GetEventHandler();
    if (!keh) {
        LOG_ERROR("GetEventHandle failed\n");
        return -1;
    }
    m_pNetAgent = pAgent;
    keh->SetSockMgr(pAgent);
    keh->Init();
    return 0;
}

void CBackendMgr::SetDriverDefaultPolicy() {

    std::string str_json_policy;
    std::string str_json_dir;

 
    if (access(POLICY_PROCESS_JSON, F_OK) == 0) {
        build_json::read_json_file(POLICY_PROCESS_JSON,str_json_policy);
    }

    if (access(POLICY_DIR_JSON, F_OK) == 0) {
        build_json::read_json_file(POLICY_DIR_JSON,str_json_dir);
    }

    CONFIG_INFO conf;
    GetConf(conf);
    if (keh) {
        keh->SetPlicyConf(conf);
    }
}

void CBackendMgr::DosetNetSyslogConf(const SYSLOG_INFO& syslog_conf_data) {
    if (keh) {
        keh->SetNetSyslogPolicy(syslog_conf_data);
    }
}   

void CBackendMgr::GetConf(CONFIG_INFO &conf) {
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
    }

}

void CBackendMgr::DoSetProcessWhite(const std::string &recvData)
{
    std::string strLoginRequestJson = recvData;
    std::map<std::string, std::string> mapProcessInfo;
    //LOG_INFO("CBackendMgr DoSetProcessWhite recv_content=%s\n", strLoginRequestJson.c_str());
    parse_json::ParaseProcessWhite(strLoginRequestJson, mapProcessInfo);
    if (keh) {
        keh->SetPolicyProcess(mapProcessInfo, 1);
    }
}

void CBackendMgr::DoSetNetPortPolicy(std::vector<PORT_REDIRECT> &vecData) {
    if (keh) {
        int i = 0;
        int index = 0;
        struct NetworkKernelPolicyInfo infoPolicy;
        memset(&infoPolicy, 0, sizeof(infoPolicy));
        std::vector<PORT_REDIRECT>::iterator iter;
        if (vecData.size() > 20) {
            LOG_ERROR("DoSetNetPortPolicy virul port tool much");
            return; 
        }

        for (i = 0, iter = vecData.begin(); iter != vecData.end(); iter++, i++) {
            std::vector<std::string> vecPort;
            std::vector<std::string>::iterator iter_douhao;
            std::vector<std::string> vecPort_pozhehao;
            infoPolicy.acl_num = vecData.size();
            infoPolicy.pol_switch = 1;

            //解析端口
            if (iter->source_port.find(",") != std::string::npos) {
                string_utils::Split(vecPort, iter->source_port, ",");

            } else {
                vecPort.push_back(iter->source_port);
            }

            for (iter_douhao = vecPort.begin(); iter_douhao != vecPort.end(); iter_douhao++) {
                vecPort_pozhehao.clear();
                if (iter_douhao->find("-") != std::string::npos ) {
                    string_utils::Split(vecPort_pozhehao, *iter_douhao, "-");
                   
                    std::string str_before = vecPort_pozhehao[0].c_str();
                    std::string str_after = vecPort_pozhehao[1].c_str();
                    infoPolicy.rules_info[index].sport = atoi(str_before.c_str());
                    infoPolicy.rules_info[index].eport = atoi(str_after.c_str());
                    //LOG_INFO("before start port:%s, berfore:%s, end port:%s, after:%s", vecPort_pozhehao[0].c_str(), str_before.c_str(), vecPort_pozhehao[1].c_str(), str_after.c_str());
                } else {
                    infoPolicy.rules_info[index].sport = atoi(iter_douhao->c_str());
                    infoPolicy.rules_info[index].eport = atoi(iter_douhao->c_str());
                }

                if (iter->source_ip == "0.0.0.0") {
                    infoPolicy.rules_info[index].sip.pad[0] = 0;
                    infoPolicy.rules_info[index].sip.pad[1] = 0;
                    infoPolicy.rules_info[index].sip.pad[2] = 0;
                    infoPolicy.rules_info[index].sip.ip4 = 1;
                } else {
                    infoPolicy.rules_info[index].sip.pad[0] = 0;
                    infoPolicy.rules_info[index].sip.pad[1] = 0;
                    infoPolicy.rules_info[index].sip.pad[2] = 0;
                    infoPolicy.rules_info[index].sip.ip4 = inet_addr(iter->source_ip.c_str());
                }
                infoPolicy.rules_info[index].eip.ip4 = inet_addr(iter->dest_ip.c_str());
                infoPolicy.rules_info[index].addr_type = (iter->alarm_level)&0x1f;
                infoPolicy.rules_info[index].redirectPort = atoi(iter->dest_port.c_str());
                infoPolicy.rules_info[index].protocol = 1;
                
                LOG_INFO("DoSetNetPortPolicy infoPolicy.acl_num :%d, infoPolicy sip:%u, sourceip:%s, sport:%u, eport:%u,souce_port:%s", infoPolicy.acl_num,
                    infoPolicy.rules_info[index].sip.ip4, iter->source_ip.c_str(), infoPolicy.rules_info[index].sport, infoPolicy.rules_info[index].eport, iter->source_port.c_str());
                index++;
            }
        }
        #if 0
        std::vector<PORT_BUSINESS_LIST>::iterator iter_bus;
        int port_index = 0;
        for (iter_bus = g_BuspotList.begin(); iter_bus != g_BuspotList.end(); iter_bus++) {
            if ( (iter_bus->nLocalPort <65535) &&  (iter_bus->nLocalPort >10)) {
                if (port_index <50) { 
                    infoPolicy.whilte_port[port_index] = iter_bus->nLocalPort;
                    port_index++;
                } else{
                    LOG_INFO("DoSetNetPortPolicy port_index >50");
                    break;
                }  
            }
        }
        #else
        #if 0 // The function of this part of the code is changed to "KernelEventHandler::UpdateBusinessPortEvent" to regularly update the business port
        m_portInfo->getNetstatinfo();
        std::map<int, PORT_BUSINESS_LIST >::iterator iter_bus;
        int port_index = 0;
        //LOG_INFO("netstat map size is %d\n", m_portInfo->netstat_map.size());
        for (iter_bus = m_portInfo->netstat_map.begin(); iter_bus != m_portInfo->netstat_map.end(); iter_bus++) {
            if ( (iter_bus->second.nLocalPort <65535) &&  (iter_bus->second.nLocalPort >10)) {
                if (port_index <50) { 
                    infoPolicy.whilte_port[port_index] = iter_bus->second.nLocalPort;
                    port_index++;
                } else{
                    LOG_INFO("DoSetNetPortPolicy port_index >50");
                    break;
                }  
            }
        }
        #endif
        #endif
        keh->SetNetPortKernelPolicy(vecData, infoPolicy);
    }
}

void CBackendMgr::DoSetProcessBlack(const std::string &recvData)
{
    std::string strLoginRequestJson = recvData;
    std::map<std::string, std::string> mapProcessInfo;
    LOG_INFO("CBackendMgr DoSetProcessBlack recv_content=%s\n", strLoginRequestJson.c_str());
    parse_json::ParaseProcessWhite(strLoginRequestJson, mapProcessInfo);
    if (keh) {
        keh->SetPolicyProcess(mapProcessInfo, 2);
    }
}

void CBackendMgr::DoSetExiportPolicy(const std::string &recvData)
{
    std::string strLoginRequestJson = recvData;
    std::vector<POLICY_EXIPOR_PROTECT> vecInfo;
    LOG_INFO("CBackendMgr DoSetExiportPolicy recv_content=%s\n", strLoginRequestJson.c_str());
    parse_json::ParaseExiportProtect(strLoginRequestJson, vecInfo);
    m_patternRule->SetExiportDir(vecInfo);
    if (keh) {
        keh->SetPolicyExiport(vecInfo);
    }
}

void CBackendMgr::DoSetSetConf(const std::string &recvData)
{
    static int self_protect_switch = -1;
    static int s_file_switch = -1, s_extortion_switch = -1;
    std::string strLoginRequestJson = recvData;
    //LOG_DEBUG("CBackendMgr DoSetSetConf recv_content=%s\n", strLoginRequestJson.c_str());
    CONFIG_INFO conf;
    parse_json::ParaseConfJson(strLoginRequestJson, conf);
    //LOG_INFO("..........syslog_process_switch :%d", conf.syslog_process_switch);
    LOG_INFO("==============file_protect=%d, file_switch=%d, extortion_switch=%d\n",conf.file_protect, conf.file_switch, conf.extortion_switch);
    if (keh) {
        keh->SetPlicyConf(conf);
        if (self_protect_switch != conf.self_protect_switch) {
            m_patternRule->AddFilePattern(conf.self_protect_switch);
            self_protect_switch = conf.self_protect_switch;
        }
        if (s_file_switch != conf.file_switch) {
            if (conf.file_switch == 0) {
                m_patternRule->ClearProtectDir();
            }
            s_file_switch = conf.file_switch;
        }
        if (s_extortion_switch != conf.extortion_switch) {
            if (conf.extortion_switch == 0) {
                m_patternRule->ClearExiportDir();
            }
            s_extortion_switch = conf.extortion_switch;
        }



        SYSLOG_INFO syslog_conf_data = {conf.api_port, conf.syslog_port, conf.syslog_process_switch, conf.proc_switch};
        keh->SetNetSyslogPolicy(syslog_conf_data);
    }
}

void CBackendMgr::DoSetDirPolicy(const std::string &recvData)
{
    std::string strLoginRequestJson = recvData;
    //LOG_INFO("CBackendMgr DoSetDirPolicy recv_content=%s\n", strLoginRequestJson.c_str());
    std::vector<POLICY_PROTECT_DIR> vecProtectDir;
    parse_json::ParaseProtectDir(strLoginRequestJson, vecProtectDir);
    if (keh) {
        m_patternRule->SetProtectDir(vecProtectDir);
        keh->SetPolicyDir(vecProtectDir);
    }
}

 void CBackendMgr::DosetNetBlockPolicy(std::vector<FirewallRule> lstFireWall) {
    if (keh) {
#if 0    
        int index = 0;
        struct NetworkKernelPolicyInfo infoPolicy;
        memset(&infoPolicy, 0, sizeof(infoPolicy));
        std::vector<FirewallRule>::iterator iter = lstFireWall.begin();
        if (lstFireWall.size() > 20) {
            LOG_ERROR("DosetNetBlockPolicy block tool much");
            return; 
        }

        for (; iter != lstFireWall.end(); iter++) {
            infoPolicy.acl_num = lstFireWall.size();
            infoPolicy.acl_type = 1;
            infoPolicy.pol_switch = 1;
            infoPolicy.rules_info[index].sport = atoi(iter->local_port.c_str());
            infoPolicy.rules_info[index].eport = atoi(iter->remote_port.c_str());
            infoPolicy.rules_info[index].sip = inet_addr(iter->local_ip.c_str());
            infoPolicy.rules_info[index].eip = inet_addr(iter->remote_ip.c_str());
            infoPolicy.rules_info[index].protocol = 1;
            LOG_INFO("CBackendMgr DosetNetBlockPolicy infoPolicy ip:%s, eip:%x\n", iter->remote_ip.c_str(), infoPolicy.rules_info[index].eip);
            index++;
        }
        keh->SetNetBlock(lstFireWall, infoPolicy);
#else
        struct NetworkKernelPolicyInfo infoPolicy;
        m_connBlock->ClearBlockList();
        memset(&infoPolicy, 0, sizeof(infoPolicy));
        infoPolicy.acl_num = lstFireWall.size();
        infoPolicy.acl_type = 1;
        infoPolicy.pol_switch = 1;
        LOG_INFO("infoPolicy.acl_num=%d\n",infoPolicy.acl_num);
        std::vector<FirewallRule>::iterator iter = lstFireWall.begin();
        for (; iter != lstFireWall.end(); iter++) {
            m_connBlock->AddIP2BlockList(iter->remote_ip);
            //infoPolicy.rules_info[index].eip = inet_addr(iter->remote_ip.c_str());
            //index++;
        }
        keh->SetNetBlock(lstFireWall, infoPolicy);
#endif
    }
 }

void CBackendMgr::DosetWhiltePolicy(std::vector<NET_PROTECT_IP> vecData) {
    keh->SettWhilteIpPolicy(vecData);
}

void CBackendMgr::DoSetBusPort(std::vector<PORT_BUSINESS_LIST> vecData) {
    g_BuspotList = vecData;
}

void CBackendMgr::DoSetSefClose() {
    keh->SetSelfEnable(0);
    keh->SetSelfProtected(0);
}

void CBackendMgr::DosetGlobalTrustDir(std::vector<GlobalTrusrDir> global_trustdir) {
//    keh->SetGlobalTrustDir(global_trustdir);
    m_patternRule->SetGlobalTrustDir(global_trustdir);
}
