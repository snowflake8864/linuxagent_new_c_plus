#ifndef PCINFO_PCINFOLINUX_H_
#define PCINFO_PCINFOLINUX_H_

#include <list>
#include <map>
#include <set>
#include <vector>
#include <string>

#define GET_ESXI_MAC     "esxcfg-vmknic -l 2>/dev/null | grep IPv4 | grep '[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]' | awk '{print $8}' | head -n 1"
#define GET_ESXI_IP      "esxcfg-vmknic -l 2>/dev/null | grep IPv4 | grep '[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]' | awk '{print $1,$5,$8}' | head -n 1"
#define GET_ESXI_IP_V6   "esxcfg-vmknic -l 2>/dev/null | grep IPv6 | grep '[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]' | awk '{print $1,$5,$7}' | head -n 1"
#define GET_ESXI_RELEASE "vmware -v 2>/dev/null"

enum IP_INFO {
    IP_V4 = 0,
    IP_V6,
    IP_UNKNOWN
};

class CPcInfoLinux {
    struct ethInfo {
        std::string m_mac;
        std::list<std::pair<IP_INFO, std::string> > m_ip;
    };
  public:
    CPcInfoLinux() {
        m_ip_type_ = IP_V4;
        GetPcInfo();
    }
    CPcInfoLinux(IP_INFO type) {
        m_ip_type_ = type;
        GetPcInfo();
    }
    ~CPcInfoLinux(){}

  public:
    std::string GetComputerName();
    std::string GetComputerVersion();
    std::string GetComputerUserName();
    std::string GetHostName();
    std::string GetReleaseVersion();
    std::string GetReportIp(const std::string &str_control_addr);
    std::string GetReportMac(const std::string &str_control_addr);
    std::string GetReportEthName() {
        return m_computer_ethname_;
    }
    void GetIPMACList(std::map<std::string, std::list<std::string> >& ip_mac_map) {
        std::map<std::string, struct ethInfo>::const_iterator iter_map = m_ethname_ip_mac_map_.begin();
        for (; iter_map != m_ethname_ip_mac_map_.end(); ++iter_map) {
            struct ethInfo eth_info = iter_map->second;
            std::list<std::pair<IP_INFO, std::string> >::iterator it = eth_info.m_ip.begin();
            std::list<std::string> ip_list;
            for (; it != eth_info.m_ip.end(); it++) {
                ip_list.push_back(it->second);
            }
            ip_mac_map[eth_info.m_mac] = ip_list;
        }
    }

  private:
    bool GetPcInfo();
    void InitOSMap();
    bool GetNetWorkCardName(std::set<std::string> &ifnames);
    bool GetEXSICardName();
    void GetEXSIInfo(const std::string& cmd, std::set<std::string>& data);
    void GetH3CInfo(std::string& info);
    bool GetIFNamesWithConfigFile(std::set<std::string> &ifnames);
    bool GetIFNamesWithIFConfig(std::set<std::string> &ifnames);
    bool GetIFConfig(int sockfd, struct ifconf* ifconf);
    void ReadIFConfig(const struct ifconf* ifconf, std::set<std::string>& ifnames);
    char* GetCardName(char *name, char *p);
    bool GetNetWorkIPMACInfo(const std::set<std::string> &ifnames);
    bool GetETHInfoWithIFName(const std::string& ifname);
    bool GetMACWithIFName(const std::string& ifname, std::string& str_mac);
    bool GetIFInfo(const std::string& ifname, int& flags);
    bool GetReleaseFileList(std::vector<std::string> &need_search_files);
    bool SortReleaseFileList(std::vector<std::string> &need_search_files);
    void GetOSNameVersion();
    std::string GetReportIPWithSocket(const std::string& str_control_addr); // ipv4
    std::string GetReportIPV6WithSocket(const std::string& str_control_addr); // ipv6 local address
    std::string GetReportGlobalAddrIPV6WithSocket(const std::string& str_control_addr); // ipv6 global address

  private:
    IP_INFO m_ip_type_;
    std::string m_computer_name_;
    std::string m_computer_version_;
    std::string m_user_name_;
    std::string m_computer_ethname_;
    std::string m_computer_ip_;
    std::string m_computer_mac_;
    std::string m_hostname_;
    std::map<std::string, struct ethInfo> m_ethname_ip_mac_map_;
    std::map<std::string, std::string> m_osmaps_;
};

#endif /* PCINFO_PCINFOLINUX_H_ */
