#include "common/utils/file_utils.h"
//#include "common/md5.h"
#include "common/json/cJSON.h"
#include "firewall.h"
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

static std::string m_module_name = "firewall";

Firewall::Firewall() {
    m_inited = false;
}
Firewall::~Firewall() {

}

int Firewall::initTailHelper()
{
    if (m_inited == true) {
        return 0;
    }
    // if (file_utils::IsFile("/sbin/iptables")) {
    //     iptables_cmd_path = "/sbin/iptables";
    // } else if (file_utils::IsFile("/usr/sbin/iptables")) {
    //     iptables_cmd_path = "/usr/sbin/iptables";
    // } else {
    //     LOG_ERROR("can not find iptables\n");
    //     return -1;
    // }
    m_inited = true;
    return 0;
}

int Firewall::Init()
{
    if(initTailHelper() != 0) {
        LOG_ERROR("init tail helper failed\n");
        return -1;
    }
    return 0;
}

std::string& Firewall::RepalceStringAllDitinct(std::string& str,
                                               const std::string& old_value,
                                               const std::string& new_value) {
    for (std::string::size_type pos(0); pos != std::string::npos;
         pos += new_value.length()) {
        if ((pos = str.find(old_value, pos)) != std::string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}

void Firewall::GetRuleCmds(const std::vector<FirewallRule>& rules)
{
    std::vector<FirewallRule>::const_iterator it;
    for (it = rules.begin(); it != rules.end(); ++it)
    {
        GetRuleCmds(*it);
    }
}

void Firewall::GetRuleCmds(const FirewallRule& rule) {
    FirewallRule sigle_rule;
    sigle_rule = rule;
    if (sigle_rule.local_port.empty()) {
        sigle_rule.local_port = "empty";
    }
    if (sigle_rule.remote_ip.empty()) {
        sigle_rule.remote_ip = "empty";
        std::string remote_port;
        std::string ptcol;
    }
    if (sigle_rule.remote_port.empty()) {
        sigle_rule.remote_port = "empty";
        std::string ptcol;
    }
    if (sigle_rule.ptcol.empty()) {
        sigle_rule.ptcol = "empty";
    }
    std::vector<std::string> remote_ips;
    std::vector<std::string> local_ports;
    std::vector<std::string> remote_ports;
    std::vector<std::string> ptcols;
    string_utils::Split(remote_ips, sigle_rule.remote_ip, ",");
    string_utils::Split(local_ports, sigle_rule.local_port, ",");
    string_utils::Split(remote_ports, sigle_rule.remote_port, ",");
    string_utils::Split(ptcols, sigle_rule.ptcol, ",");

    std::vector<std::string>::const_iterator it_remote_ips;
    std::vector<std::string>::const_iterator it_local_ports;
    std::vector<std::string>::const_iterator it_remote_ports;
    std::vector<std::string>::const_iterator it_ptcols;

    for (it_remote_ips = remote_ips.begin(); it_remote_ips != remote_ips.end();
         ++it_remote_ips) {
        sigle_rule.remote_ip = *it_remote_ips;
        for (it_local_ports = local_ports.begin();
             it_local_ports != local_ports.end(); ++it_local_ports) {
            sigle_rule.local_port = *it_local_ports;
            for (it_remote_ports = remote_ports.begin();
                 it_remote_ports != remote_ports.end(); ++it_remote_ports) {
                sigle_rule.remote_port = *it_remote_ports;
                for (it_ptcols = ptcols.begin(); it_ptcols != ptcols.end();
                     ++it_ptcols) {
                    sigle_rule.ptcol = *it_ptcols;

                    if (sigle_rule.direction == 3) {
                        sigle_rule.direction = 1;
                        GetSingleRuleCmd(sigle_rule);
                        sigle_rule.direction = 2;
                        GetSingleRuleCmd(sigle_rule);
                        sigle_rule.direction = 3;
                    } else {
                        GetSingleRuleCmd(sigle_rule);
                    }
                }
            }
        }
    }
}

void Firewall::GetSingleRuleCmd(const FirewallRule& rule) {
    std::string cmd;
    cmd += iptables_cmd_path + " -A ";

    if (rule.direction == 1) {
        cmd += "INPUT";
        if (rule.remote_ip != "empty" &&
            rule.remote_ip.find('-') == std::string::npos) {
            cmd += " -s " + rule.remote_ip;
        } else if (rule.remote_ip.find('-') != std::string::npos) {
            cmd += " -m iprange --src-range " + rule.remote_ip;
        }
    } else if (rule.direction == 2) {
        cmd += "OUTPUT";
        if (rule.remote_ip != "empty" &&
            rule.remote_ip.find('-') == std::string::npos) {
            cmd += " -d " + rule.remote_ip;
        } else if (rule.remote_ip.find('-') != std::string::npos) {
            cmd += " -m iprange --dst-range " + rule.remote_ip;
        }
    } else {
        LOG_ERROR("firewall rule error: invalid direction %d\n",
                  rule.direction);
        return;
    }

    if (rule.ptcol == "6") {
        cmd += " -p tcp";
    } else if (rule.ptcol == "17") {
        cmd += " -p udp";
    } else if (rule.ptcol == "1") {
        cmd += " -p icmp";
    } else {
        LOG_ERROR("firewall rule error: invalid ptcol %s\n",
                  rule.ptcol.c_str());
        return;
    }

    if (rule.direction == 1) {
        if (rule.ptcol == "6" || rule.ptcol == "17") {
            if ( (rule.remote_port != "empty") && (rule.remote_port != "*")) {
                std::string port = rule.remote_port;
                cmd += " --sport " + RepalceStringAllDitinct(port, "-", ":");
            }
            if ((rule.local_port != "empty") && (rule.local_port != "*")) {
                std::string port = rule.local_port;
                cmd += " --dport " + RepalceStringAllDitinct(port, "-", ":");
            }
        }
    } else if (rule.direction == 2) {
        if (rule.ptcol == "6" || rule.ptcol == "17") {
            if ((rule.remote_port != "empty") && (rule.remote_port != "*")) {
                std::string port = rule.remote_port;
                cmd += " --dport " + RepalceStringAllDitinct(port, "-", ":");
            }
            if ((rule.local_port != "empty") && (rule.local_port != "*")) {
                std::string port = rule.local_port;
                cmd += " --sport " + RepalceStringAllDitinct(port, "-", ":");
            }
        }
    }

    std::string op_cmd;
    if (rule.operation == 2) {
        op_cmd = cmd + " -j ACCEPT";
    } else if (rule.operation == 1) {
        op_cmd = cmd + " -j DROP";
    } else {
        LOG_ERROR("firewall rule error: invalid operation %d\n",
                  rule.operation);
        return;
    }

    if (rule.need_log) {
        std::stringstream ss;
        ss << rule.id;
        std::string log_cmd = cmd + " -j LOG --log-prefix \"osecfirewall[" +
                              ss.str() + "]: \" --log-level 6; ";
        cmd = log_cmd + op_cmd;
    } else {
        cmd = op_cmd;
    }

    Firewall::super_system(cmd.c_str(), m_module_name.c_str());
}

void Firewall::SetFirewall(const std::vector<FirewallRule>& rules) {
    //ClearFirewall();
    //SetWhite(m_server_ip, m_server_port);

    m_rules_map.clear();
    if (rules.size() == 0) {
        return;
    }

    std::vector<std::vector<FirewallRule> > rules_priority_vector;
    rules_priority_vector.resize(5);
    std::vector<FirewallRule>::const_iterator it;
    for (it = rules.begin(); it != rules.end(); ++it) {
        if (it->priority >= 0 && it->priority <= 4) {
            rules_priority_vector[it->priority].push_back(*it);
            m_rules_map.insert(std::pair<int, FirewallRule>(it->id, *it));
        } else {
            LOG_ERROR("firewall rule error: invalid priority %d\n",
                      it->priority);
        }
    }
}

void Firewall::SetWhite(const std::string& ip, const std::string& port) {
    std::vector<FirewallRule> rules;
    {
        FirewallRule rule;
        rule.id = -1;
        rule.name = "white";
        rule.operation = 2;
        rule.direction = 3;
        rule.remote_ip = ip;
        rule.remote_port = port;
        rule.local_port = "empty";
        rule.ptcol = "6,17,1";
        rule.need_log = false;
        rules.push_back(rule);
    }
    GetRuleCmds(rules);
}

bool Firewall::super_system(const char* cmd, const char* module_name) {
    if (cmd == NULL) {
        return false;
    }
    char cur_module_name[128];
    memset(cur_module_name, 0, sizeof(cur_module_name));
    if (module_name != NULL){
        strcpy(cur_module_name, module_name);
    }

    LOG_INFO("do %s cmd: %s", cur_module_name, cmd)
    int status = system(cmd);
    if (status < 0) {
        LOG_ERROR("do %s cmd error: %s", cur_module_name, strerror(errno));
        return false;
    }

    if (WIFEXITED(status)) {
        //取得cmdstring执行结果
        LOG_INFO("%s cmd normal termination, exit status = %d", cur_module_name,
            WEXITSTATUS(status));
        return WEXITSTATUS(status) == 0 ? true : false;

    } else if (WIFSIGNALED(status)) {
        //如果cmdstring被信号中断，取得信号值
        LOG_ERROR("%s cmd abnormal termination,signal number = %d", cur_module_name,
            WTERMSIG(status));
        return false;

    } else if (WIFSTOPPED(status)) {
        //如果cmdstring被信号暂停执行，取得信号值
        LOG_ERROR("%s cmd process stopped, signal number = %d", cur_module_name,
            WSTOPSIG(status));
        return false;

    } else {
        //如果cmdstring被信号暂停执行，取得信号值
        LOG_ERROR("Unknown Error when do %s cmd: %s", cur_module_name, cmd);
        return false;
    }
    return true;
}

void Firewall::RedirectWall(const FirewallRule& rules, int type) {
    std::string cmd;
    cmd += iptables_cmd_path + " -t nat -A OUTPUT -p tcp -d ";
    cmd += rules.local_ip;
    cmd += " --dport ";
    cmd += rules.local_port;
    cmd += " -j DNAT --to ";
    cmd += rules.remote_ip;
    cmd += ":";
    cmd += rules.remote_port;
    Firewall::super_system(cmd.c_str(), m_module_name.c_str());
}

// 获取本机ip
int Firewall::get_local_ip(const char *eth_inf, char *ip)
{

#define MAC_SIZE    18
#define IP_SIZE     16
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd)
    {
        printf("socket error: %s\n", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, eth_inf, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    // if error: No such device
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return -1;
    }

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    snprintf(ip, IP_SIZE, "%s", inet_ntoa(sin.sin_addr));

    close(sd);
    return 0;
}

void Firewall::SetIpBlack(std::vector<FirewallRule>& rules)
{
    std::vector<FirewallRule>::iterator iter;
    char buff_cmd[1024] = {0};
    for (iter = rules.begin(); iter != rules.end(); iter++) 
    {
        if (iter->operation == 2) {
            continue;
        }
        if ( (iter->direction == 1) || (iter->direction == 3)){
            sprintf(buff_cmd, "iptables -I INPUT -s %s -j DROP", iter->remote_ip.c_str());
            Firewall::super_system(buff_cmd, m_module_name.c_str());
        } else if ((iter->direction == 2) || (iter->direction == 3)) {
            sprintf(buff_cmd, "iptables -I OUTPUT -d %s -j DROP", iter->remote_ip.c_str());
            Firewall::super_system(buff_cmd, m_module_name.c_str());
        }
    }
}

void  Firewall::SetIpBlockIpTime(std::vector<FirewallRule>& rules) {
    std::vector<FirewallRule>::iterator iter;
    char buff_cmd[1024] = {0};
    for (iter = rules.begin(); iter != rules.end(); iter++) 
    {
        if (iter->operation == 2) {
            continue;
        }
        if ( (iter->direction == 1) || (iter->direction == 3)){
            sprintf(buff_cmd, "iptables -I INPUT -s %s -j DROP", iter->remote_ip.c_str());
            Firewall::super_system(buff_cmd, m_module_name.c_str());
        } else if ((iter->direction == 2) || (iter->direction == 3)) {
            sprintf(buff_cmd, "iptables -I OUTPUT -d %s -j DROP", iter->remote_ip.c_str());
            Firewall::super_system(buff_cmd, m_module_name.c_str());
        }
    }
}
