#include "net_mgr.h"
#include <sys/stat.h>
#include <pwd.h>
#include "common/md5sum.h"
#include "common/utils/string_utils.hpp"
#include "common/log/log.h"

static std::vector<NET_PROTECT_IP> g_white_net;
static std::vector<NET_PROTECT_IP> g_black_net;

static std::vector<FirewallRule> g_black_white_net;
static std::vector<FirewallRule> g_lstNetIP_redirect;
static std::vector<FirewallRule> g_lstNetIP_block;
static std::vector<FirewallRule> g_lstNetIP_black_block;
static std::vector<FirewallRule> g_lstNetIP_dynamic_block;
int CNet_MGR::SetNetWhitePolicy(std::vector<NET_PROTECT_IP> &lstNetIP) {
    g_white_net.clear();
    g_white_net = lstNetIP;
    std::vector<NET_PROTECT_IP> ip_net_rules;
    ip_net_rules = g_white_net;
    ip_net_rules.insert(ip_net_rules.end(), g_black_net.begin(), g_black_net.end());

    std::vector<FirewallRule> vecFirewall;
    std::vector<NET_PROTECT_IP>::iterator iter;
    for (iter = ip_net_rules.begin(); iter != ip_net_rules.end(); iter++) {
        FirewallRule rules;
        rules.id = 1;
        rules.operation = iter->type;  // 1拒绝 2允许
        rules.priority = 3;  // 0最低 1低 2普通 3高 4最高
        rules.direction = iter->direction;  // 1流入 2流出 3任意
        rules.name = "osec";
        //rules.local_port = "";
        rules.remote_ip = iter->ip;
        //rules.remote_port;
        rules.ptcol = 6;  // 协议 6:TCP 17:UDP 6,17TCP+UDP 1:ICMP
        rules.need_log = true;
        vecFirewall.push_back(rules);
    }
    g_black_white_net.clear();
    g_black_white_net = vecFirewall;
    return 0;
}

int CNet_MGR::SetNetBlackPolicy(std::vector<NET_PROTECT_IP> &lstNetIP) {
    g_black_net.clear();
    g_black_net = lstNetIP;
    std::vector<NET_PROTECT_IP> ip_net_rules; 
    ip_net_rules = g_black_net;
    ip_net_rules.insert(ip_net_rules.end(), g_white_net.begin(), g_white_net.end());
    std::vector<FirewallRule> vecFirewall;
    std::vector<NET_PROTECT_IP>::iterator iter;
    LOG_INFO("begin SetNetBlackPolicy ............");
    int i = 0;
    for (iter = ip_net_rules.begin(); iter != ip_net_rules.end(); iter++) {
        LOG_INFO("SetNetBlackPolicy ip_net_rules ip:%s, type:%d, direct:%d", iter->ip.c_str(), iter->type, iter->direction);
        FirewallRule rules;
        rules.id = i++;
        rules.operation = iter->type;  // 1拒绝 2允许
        rules.priority = 3;  // 0最低 1低 2普通 3高 4最高
        rules.direction = iter->direction;  // 1流入 2流出 3任意
        rules.name = "osec";
        //rules.local_port = "";
        rules.remote_ip = iter->ip;
        //rules.remote_port;
        rules.ptcol = 6;  // 协议 6:TCP 17:UDP 6,17TCP+UDP 1:ICMP
        rules.need_log = true;
        vecFirewall.push_back(rules);
    }
    g_black_white_net.clear();
    g_black_white_net = vecFirewall;
    //g_lstNetIP_block = vecFirewall;
    g_lstNetIP_black_block.clear();
    g_lstNetIP_black_block = vecFirewall;
    return 0;
}


int CNet_MGR::SetNetBlockList(std::vector<NETBLOCK> &lstNetIP) {
    std::vector<NETBLOCK>::iterator iter;
    std::vector<FirewallRule> vecFirewall;
    //g_lstNetIP_block.clear();
    for (iter = lstNetIP.begin(); iter != lstNetIP.end(); iter++) {
        FirewallRule rules;
        rules.id = 0;
        rules.operation = 1;  // 1拒绝 2允许
        rules.priority = 3;  // 0最低 1低 2普通 3高 4最高
        rules.direction = iter->direction;  // 1流入 2流出 3任意
        rules.name = iter->typeName;
        //rules.local_port ;
        rules.remote_ip = iter->ip;
        //rules.remote_port;
        rules.ptcol = 6;  // 协议 6:TCP 17:UDP 6,17TCP+UDP 1:ICMP
        rules.need_log = true;
        vecFirewall.push_back(rules);
    }
//    g_lstNetIP_block = vecFirewall;
    g_lstNetIP_dynamic_block.clear();
    g_lstNetIP_dynamic_block = vecFirewall;
    return 0;   
}
#if 0
 int CNet_MGR::GetNetPolicy(std::vector<FirewallRule>& lstFireWall) {
    lstFireWall.clear();
    LOG_INFO("0000================GetNetPolicy size=%d\n", lstFireWall.size());
    lstFireWall = g_black_white_net;
    LOG_INFO("111================GetNetPolicy size=%d\n", lstFireWall.size());
    std::vector<FirewallRule>::iterator iter;
    for (iter = g_lstNetIP_block.begin(); iter != g_lstNetIP_block.end(); iter++) {
        LOG_INFO("2222================GetNetPolicy size=%d,[%s]\n", lstFireWall.size(),iter->remote_ip.c_str());
        lstFireWall.push_back(*iter);
        LOG_INFO("333================GetNetPolicy size=%d\n", lstFireWall.size());
    }
    return 0;
 }
 #else
 int CNet_MGR::GetNetPolicy(std::vector<FirewallRule>& lstFireWall) {
    lstFireWall.clear();
    std::vector<FirewallRule>::iterator iter;
    for (iter = g_lstNetIP_dynamic_block.begin(); iter != g_lstNetIP_dynamic_block.end(); iter++) {
        lstFireWall.push_back(*iter);
    }
    for (iter = g_lstNetIP_black_block.begin(); iter != g_lstNetIP_black_block.end(); iter++) {
        lstFireWall.push_back(*iter);
    }
    return 0;
 }


 #endif
