#ifndef FIREWALL_H
#define FIREWALL_H

#include "common/log/log.h"
#include "osec_common/global_message.h"

class Firewall {
public:
    Firewall();
    ~Firewall();
    int Init();
    void SetFirewall(const std::vector<FirewallRule>& rules);
    int  get_local_ip(const char *eth_inf, char *ip);
    void  SetIpBlack(std::vector<FirewallRule>& rules);
    void  SetIpBlockIpTime(std::vector<FirewallRule>& rules);
    
private:
    int initTailHelper();
    void SetWhite(const std::string& ip, const std::string& port);
    bool super_system(const char* cmd,const char* module_name);
private:
    std::map<int, FirewallRule> m_rules_map;
    std::string m_server_ip;
    std::string m_server_port;
    std::string iptables_cmd_path;
    bool m_inited;
};

#endif  // FIREWALL_H
