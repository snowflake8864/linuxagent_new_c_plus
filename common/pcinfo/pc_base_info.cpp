#include "pcinfo/pc_base_info.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <stddef.h>
#include <set>
#include <sstream>
#include <utility>
#include <vector>
#include "log/log.h"
#include "utils/file_utils.h"
#include "utils/string_utils.hpp"

bool CPcInfoLinux::GetPcInfo() {
    InitOSMap(); 
    if (true == GetEXSICardName()) {
        LOG_DEBUG("the computer type is exsi.");
        return true;
    }
    std::set<std::string> ifnames;
    if (false == GetNetWorkCardName(ifnames) && ifnames.size() <= 0) {
        LOG_ERROR("get the network card name failed.");
        return false;
    }
    if (false == GetNetWorkIPMACInfo(ifnames)) {
        LOG_ERROR("get the network ip mac failed.");
        return false;
    }

    return true;
}

bool CPcInfoLinux::GetEXSICardName() {
    //try get esxi mac addr first
    std::set<std::string> esxi_eth_info;
    std::string cmd = GET_ESXI_IP;
    if (m_ip_type_ == IP_V6) {
        cmd = GET_ESXI_IP_V6;
    }
    GetEXSIInfo(cmd, esxi_eth_info);
    if (esxi_eth_info.empty()) {
        LOG_ERROR("get esxi eth info failed, ip type[%s].", (m_ip_type_ == IP_V4 ? "ipv4" : "ipv6"));
        return false;
    }

    for(std::set<std::string>::iterator it = esxi_eth_info.begin(); it != esxi_eth_info.end(); it++) {
        std::vector<std::string> strRes;
        string_utils::Split(strRes, *it, " ");
        if (strRes.size() != 3) {
            LOG_DEBUG("get esxi eth info format invalid.");
            continue;
        }
        std::string eth_name = strRes[0];
        std::string eth_mac = strRes[1];
        std::string eth_ip = strRes[2];
        if (m_ethname_ip_mac_map_.find(eth_name) != m_ethname_ip_mac_map_.end()) {
            m_ethname_ip_mac_map_[eth_name].m_ip.push_back(std::make_pair(m_ip_type_, eth_ip));
        } else {
            struct ethInfo eth_info;
            eth_info.m_mac = eth_mac;
            eth_info.m_ip.push_back(std::make_pair(m_ip_type_, eth_ip));
            m_ethname_ip_mac_map_[eth_name] = eth_info;
        }
    }
    if (m_ethname_ip_mac_map_.empty()) return false;
    return true;
}

void CPcInfoLinux::GetEXSIInfo(const std::string& cmd, std::set<std::string>& data) {
    FILE * pread = popen(cmd.c_str(), "r");
    if (pread == NULL) {
        LOG_ERROR("popen cmd[%s] failed, because: %s[%d].", cmd.c_str(), strerror(errno), errno);
        return;
    }

    char buf[128];
    memset(buf, '\0', sizeof(buf));
    while (fgets(buf, 127, pread) != NULL) {
        std::string tmp_data = std::string(buf, 127);
        size_t index = tmp_data.find('\n');
        if (index != std::string::npos) {
            tmp_data = std::string(buf, index);
            data.insert(tmp_data);
        }
    }
    pclose(pread);
}

bool CPcInfoLinux::GetNetWorkCardName(std::set<std::string> &ifnames) {
    if (true == GetIFNamesWithConfigFile(ifnames) && ifnames.size() == 0) {
        return GetIFNamesWithIFConfig(ifnames);
    }
    return true;
}

bool CPcInfoLinux::GetIFConfig(int sockfd, struct ifconf* ifconf) {
    ifconf->ifc_buf = NULL;
    int numreqs = 30;
    for (;;) {
        ifconf->ifc_len = numreqs * sizeof(struct ifreq);
        ifconf->ifc_buf = (char*)realloc(ifconf->ifc_buf, ifconf->ifc_len);

        if (ioctl(sockfd, SIOCGIFCONF, ifconf) < 0) {
            if(ifconf->ifc_buf) { free(ifconf->ifc_buf); }
            return false;
        }

        if (ifconf->ifc_len == numreqs * static_cast<int>(sizeof(struct ifreq))) {
            /* assume it overflowed and try again */
            numreqs += 10;
            continue;
        }
        break;
    }

    return true;
}

void CPcInfoLinux::ReadIFConfig(const struct ifconf* ifconf, std::set<std::string>& ifnames) {
    struct ifreq *ifreq;
    ifreq = (struct ifreq*)ifconf->ifc_buf;
    int index = (ifconf->ifc_len / sizeof(struct ifreq));
    for ( ; index>0; index--) {
        ifnames.insert(ifreq->ifr_name);
        ifreq++;
    }
}

bool CPcInfoLinux::GetIFNamesWithIFConfig(std::set<std::string> &ifnames) {
    int sockfd;
    struct ifconf ifconf;
    memset(&ifconf, 0, sizeof(ifconf));

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG_ERROR("create socket failed, because: %s.", strerror(errno));
        return false;
    }
    if (GetIFConfig(sockfd, &ifconf) == false) {
        LOG_ERROR("call GetIFConfig failed.");
        close(sockfd);
        return false;
    }
    close(sockfd);
    ReadIFConfig(&ifconf, ifnames);
    free(ifconf.ifc_buf);
    return true;
}

bool CPcInfoLinux::GetIFNamesWithConfigFile(std::set<std::string> &ifnames) {
    FILE *fh = fopen("/proc/net/dev", "r");
    bool rtn = false;
    do {
        if (!fh) {
            LOG_ERROR("get network card info file[%s] failed.", "/proc/net/dev");
            break;
        }
        char buf[512] = { 0 };
        /* eat line */
        if (fgets(buf, sizeof(buf), fh) == NULL) {
            break;
        }
        memset(buf, 0, sizeof(buf));
        if (fgets(buf, sizeof(buf), fh) == NULL) {
            break;
        }
        while (fgets(buf, sizeof(buf), fh)) {
            char *s, name[1024] = { 0 };
            s = GetCardName(name, buf);
            if (s != NULL) {
                LOG_DEBUG("get network card name[%s]", name);
                ifnames.insert(name);
            } else {
                LOG_ERROR("get network card name failed, read the next line.");
            }
            memset(buf, 0, sizeof(buf));
        }
        rtn = true;
    } while (false);
    if (NULL != fh) fclose(fh);
    return rtn;
}

bool CPcInfoLinux::GetNetWorkIPMACInfo(const std::set<std::string> &ifnames) {
    std::set<std::string>::const_iterator it = ifnames.begin();
    for (; it != ifnames.end(); it++) {
        bool rc = GetETHInfoWithIFName(it->c_str());
        if (rc == false) {
            LOG_ERROR("get eth info with ifname[%s] failed.", it->c_str());
            continue;
        }
        LOG_DEBUG("get eth info with ifname[%s] success.", it->c_str());
    }

    return (m_ethname_ip_mac_map_.empty() ? false : true);
}

bool CPcInfoLinux::GetMACWithIFName(const std::string& ifname, std::string& str_mac) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG_ERROR("get mac failed, carete socket[AF_INET] failed, because: %s", strerror(errno));
        return false;
    }

    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    memcpy(ifr.ifr_name,ifname.c_str(),ifname.size());
    ifr.ifr_addr.sa_family = AF_INET;

    int rtn = ioctl(sockfd, SIOCGIFHWADDR, &ifr);

    if (rtn < 0) {
        LOG_ERROR("get mac failed, ioctl[SIOCGIFHWADDR] failed, because: %s", strerror(errno));
        if (sockfd > 0) close(sockfd);
        return false;
    }
    if (sockfd > 0) close(sockfd);

    char mac[64] = {0};
    snprintf(mac,sizeof(mac),"%02x%02x%02x%02x%02x%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    str_mac = mac;
    return true;
}

bool CPcInfoLinux::GetIFInfo(const std::string& ifname, int& flags) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname.c_str(), ifname.size());

    int sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if (sockfd < 0) {
        LOG_ERROR("get if info failed, socket failed, because: %s[%d].", strerror(errno), errno);
        return false;
    }

    if (ioctl(sockfd,SIOCGIFFLAGS,&ifr) < 0) {
        LOG_ERROR("get if info failed, ioctl[SIOCGIFFLAGS] failed, because: %s", strerror(errno));
        close(sockfd);
        return false;
    }
    close(sockfd);
    flags = ifr.ifr_flags;

    return true;
}

bool CPcInfoLinux::GetETHInfoWithIFName(const std::string& ifname) {
    struct ifaddrs *ifaddr;
    if (-1 == getifaddrs(&ifaddr))
        return false;
    int sa_family = AF_INET;
    if (m_ip_type_ == IP_V6) {
        sa_family = AF_INET6;
    }
    for(struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        std::string eth_ip;
        std::string eth_mac;
        if(ifa->ifa_name && !strcmp(ifa->ifa_name, ifname.c_str()) && ifa->ifa_addr && ifa->ifa_addr->sa_family == sa_family) {
            char ip_str[64];
            memset(ip_str, '\0', sizeof(ip_str));
            if (m_ip_type_ == IP_V6) {
                struct sockaddr_in6 s;
                memcpy(&s, ifa->ifa_addr, sizeof(struct sockaddr_in6));
                inet_ntop(sa_family, &s.sin6_addr, ip_str, sizeof(ip_str));
            } else {
                struct sockaddr_in s;
                memcpy(&s, ifa->ifa_addr, sizeof(struct sockaddr_in));
                inet_ntop(sa_family, &s.sin_addr, ip_str, sizeof(ip_str));
            }
            eth_ip = std::string(ip_str);
            if (eth_ip.empty()) {
                LOG_ERROR("get mac with ifname[%s] format error, ip is null.", ifname.c_str());
                continue;
            } else {
                LOG_DEBUG("get ip with ifname[%s], ip = %s.", ifname.c_str(), eth_ip.c_str());
            }
            bool rc = GetMACWithIFName(ifname, eth_mac);
            if (rc == false) {
                LOG_ERROR("get mac with ifname[%s] failed.", ifname.c_str());
                continue;
            }
            if (eth_mac != "000000000000") {
                int ifflags = 0;
                GetIFInfo(ifname.c_str(), ifflags);
                //接口状态一定要是UP,RUNNING且为非LOOPBack接口
                rc = (((ifflags & IFF_UP) && ifflags & IFF_RUNNING) && (!(ifflags & IFF_LOOPBACK)));
                if (rc == false) {
                    LOG_ERROR("the eth status[%d] is invalid.", ifflags);
                    continue;
                } else {
                    LOG_DEBUG("get mac with ifname[%s], mac = %s.", ifname.c_str(), eth_mac.c_str());
                }
                if (m_ethname_ip_mac_map_.find(ifname) != m_ethname_ip_mac_map_.end()) {
                    m_ethname_ip_mac_map_[ifname].m_ip.push_back(std::make_pair(m_ip_type_, eth_ip));
                } else {
                    struct ethInfo eth_info;
                    eth_info.m_mac = eth_mac;
                    eth_info.m_ip.push_back(std::make_pair(m_ip_type_, eth_ip));
                    m_ethname_ip_mac_map_[ifname] = eth_info;
                }
            } else {
                LOG_ERROR("get mac with finame[%s] format error, mac = %s.", ifname.c_str(), eth_mac.c_str());
            }
        }
    }
    return true;
}

std::string CPcInfoLinux::GetReportIp(const std::string &str_control_addr) {
    if (str_control_addr.empty() || !m_computer_ip_.empty()) {
        return m_computer_ip_;
    }
    if(str_control_addr.empty()) return "";
    if (m_ip_type_ == IP_V4) {
        return GetReportIPWithSocket(str_control_addr);
    } else if (str_control_addr.find("[fe80") != std::string::npos) {
        return GetReportIPV6WithSocket(str_control_addr);
    } else {
        return GetReportGlobalAddrIPV6WithSocket(str_control_addr);
    }
    if (m_computer_ip_.empty()) {
        return GetReportIPWithSocket(str_control_addr);
    }
}

std::string CPcInfoLinux::GetReportIPWithSocket(const std::string& str_control_addr) {
    sockaddr_in serveraddr = { 0 };
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        LOG_ERROR("get report ip failed, carete socket[AF_INET, IPPROTO_TCP] failed, because: %s", strerror(errno));
        return "";
    }

    std::string::size_type nPos = str_control_addr.find(":");
    if (nPos == std::string::npos) {
       LOG_ERROR("get report ip serverip[%s] format wrong", str_control_addr.c_str());
        return "";
    }
    std::string strIp = str_control_addr.substr(0, nPos);
    std::string strPort = str_control_addr.substr(nPos + 1, str_control_addr.length());

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(strIp.c_str());
    serveraddr.sin_port = htons(atoi(strPort.c_str()));

    struct timeval tv ={3, 10000};
    socklen_t tv_len = socklen_t(sizeof(timeval));

    do {
        int nRet = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, tv_len);
        if (nRet < 0) {
            LOG_ERROR("get report ip failed, setsockopt[SO_SNDTIMEO] failed.");
            break;
        }

        nRet = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, tv_len);
        if (nRet < 0) {
            LOG_ERROR("get report ip failed, setsockopt[SO_RCVTIMEO] failed.");
            break;
        }

        nRet = connect(sockfd, (sockaddr*)&serveraddr, sizeof(serveraddr));
        if (nRet < 0) {
            LOG_ERROR("get report ip failed, connect failed.");
            break;
        }

        sockaddr_in selfaddr = { 0 };
        int nLen = sizeof(selfaddr);
        if (getsockname(sockfd, (sockaddr*)&selfaddr, (socklen_t *)&nLen) >= 0) {
            char *pszCurIP = inet_ntoa(selfaddr.sin_addr);
            m_computer_ip_ = pszCurIP;
            LOG_DEBUG("get report ip success, report_ip[%s]", m_computer_ip_.c_str());
        }
    } while (false);

    if (sockfd > 0) close(sockfd);

    return m_computer_ip_;
}

std::string CPcInfoLinux::GetReportIPV6WithSocket(const std::string& str_control_addr) {
    std::string::size_type nPos = str_control_addr.find("]:");
    if (nPos == std::string::npos) return "";
    std::string strIp = str_control_addr.substr(1, nPos - 1);
    std::string strPort = str_control_addr.substr(nPos+2, str_control_addr.length());

    std::map<std::string, struct ethInfo>::iterator iter_map = m_ethname_ip_mac_map_.begin();
    for (; iter_map != m_ethname_ip_mac_map_.end(); ++iter_map) {
        struct ethInfo eth_info = iter_map->second;
        std::list<std::pair<IP_INFO, std::string> >::iterator it = eth_info.m_ip.begin();
        for (; it != eth_info.m_ip.end(); it++) {
            if ((*it).first == IP_V4) continue;
            struct addrinfo hints = { 0 };
            struct addrinfo *res;
            hints.ai_family = AF_INET6;
            hints.ai_socktype = SOCK_STREAM;
            char data[1024] = { 0 };
            sprintf(data, "%s%s%s", strIp.c_str(), "%", iter_map->first.c_str());
            int gai_err = getaddrinfo(data, strPort.c_str(), &hints, &res);
            if (gai_err) {
                LOG_ERROR("get ipv6 local address[getaddrinfo] failed, because: %s[%d].", strerror(errno), errno);
                continue;
            }

            int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (sockfd < 0) {
                LOG_ERROR("get ipv6 local address[socket] failed, because: %s[%d].", strerror(errno), errno);
                continue;
            }
            if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
                LOG_ERROR("get ipv6 local address[connect] failed, because: %s[%d].", strerror(errno), errno);
                continue;
            }

            struct sockaddr_in6 selfaddr = { 0 };
            int nLen = sizeof(selfaddr);
            if (getsockname(sockfd, (sockaddr*)&selfaddr, (socklen_t *)&nLen) >= 0) {
                char pszCurIP[256] = {0};
                inet_ntop(AF_INET6, &selfaddr.sin6_addr, pszCurIP, sizeof(pszCurIP));
                m_computer_ip_ = pszCurIP;
                m_computer_ethname_ = iter_map->first;
            }

            close(sockfd);
            break;
        }
        if (!m_computer_ip_.empty()) break;
    }
    return m_computer_ip_;
}

std::string CPcInfoLinux::GetReportGlobalAddrIPV6WithSocket(const std::string& str_control_addr) {
    std::string::size_type nPos = str_control_addr.find("]:");
    if (nPos == std::string::npos) return "";
    std::string strIp = str_control_addr.substr(1, nPos - 1);
    std::string strPort = str_control_addr.substr(nPos+2, str_control_addr.length());

    struct addrinfo hints = { 0 };
    struct addrinfo *res;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    char data[1024] = { 0 };
    sprintf(data, "%s", strIp.c_str());
    int gai_err = getaddrinfo(data, strPort.c_str(), &hints, &res);
    if (gai_err) {
        LOG_ERROR("get ipv6 global address[getaddrinfo] failed, because: %s[%d].", strerror(errno), errno);
        return "";
    }

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        LOG_ERROR("get ipv6 global address[socket] failed, because: %s[%d].", strerror(errno), errno);
        return "";
    }
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        LOG_ERROR("get ipv6 global address[connect] failed, because: %s[%d].", strerror(errno), errno);
        return "";
    }

    struct sockaddr_in6 selfaddr = { 0 };
    int nLen = sizeof(selfaddr);
    if (getsockname(sockfd, (sockaddr*)&selfaddr, (socklen_t *)&nLen) >= 0) {
        char pszCurIP[256] = {0};
        inet_ntop(AF_INET6, &selfaddr.sin6_addr, pszCurIP, sizeof(pszCurIP));
        m_computer_ip_ = pszCurIP;
    }

    close(sockfd);

    return m_computer_ip_;
}

std::string CPcInfoLinux::GetReportMac(const std::string &str_control_addr) {
    if(str_control_addr.empty() || !m_computer_mac_.empty()) {
        return m_computer_mac_;
    }
    if(m_computer_ip_.empty()) {
        m_computer_ip_ = GetReportIp(str_control_addr);
    }
    std::map<std::string, struct ethInfo>::iterator iter_map = m_ethname_ip_mac_map_.begin();
    for (; iter_map != m_ethname_ip_mac_map_.end(); ++iter_map) {
        struct ethInfo eth_info = iter_map->second;
        std::list<std::pair<IP_INFO, std::string> >::iterator it = eth_info.m_ip.begin();
        for (; it != eth_info.m_ip.end(); it++) {
            if (m_computer_ip_ == it->second) {
                m_computer_mac_ = eth_info.m_mac;
                break;
            }
        }
    }
    return m_computer_mac_;
}

std::string CPcInfoLinux::GetComputerUserName() {
    if (!m_user_name_.empty())
        return m_user_name_;

    uid_t uid;
    uid = getuid();
    struct passwd * pwd = getpwuid(uid);
    if (!pwd || !pwd->pw_name)
        return m_user_name_;

    m_user_name_ = pwd->pw_name;

    return m_user_name_;
}

char* CPcInfoLinux::GetCardName(char *name, char *p) {
    while (isspace(*p))
        p++;
    while (*p) {
        if (isspace(*p))
            break;
        if (*p == ':') {
            char *dot = p, *dotname = name;
            *name++ = *p++;
            while (isdigit(*p))
                *name++ = *p++;
            if (*p != ':') {
                p = dot;
                name = dotname;
            }
            if (*p == '\0')
                return NULL;
            p++;
            break;
        }
        *name++ = *p++;
    }
    *name++ = '\0';
    return p;
}

std::string CPcInfoLinux::GetHostName() {
    if (!m_hostname_.empty())
        return m_hostname_;
    char strhostname[1024] = {0};
    size_t len = sizeof(strhostname) - 1;
   // struct utsname name = {0};
    struct utsname name;
    if (uname(&name) == -1) {
        LOG_ERROR("uname get hostname failed, because:%s[%d].", strerror(errno), errno);
        return GetComputerName();
    }
    if (strlen(name.nodename) > len) {
        LOG_ERROR("uname get nodename is longer than 1024.");
        return GetComputerName();
    }
    strcpy(strhostname, name.nodename);
    len = strlen(strhostname);
    m_hostname_.assign(strhostname, len);
    return m_hostname_;
}

std::string CPcInfoLinux::GetComputerName() {
    if (!m_computer_name_.empty())
        return m_computer_name_;
    GetOSNameVersion();
    return m_computer_name_;
}

std::string CPcInfoLinux::GetComputerVersion() {
    if (!m_computer_version_.empty())
        return m_computer_version_;
    GetOSNameVersion();
    return m_computer_version_;
}

std::string CPcInfoLinux::GetReleaseVersion() {
    //try get esxi release info first
    std::set<std::string> esxi_release_info;
    std::string cmd;
    cmd = GET_ESXI_RELEASE;
    GetEXSIInfo(cmd, esxi_release_info);
    if (!esxi_release_info.empty())
        return (*esxi_release_info.begin());

    //try get h3c release info
    std::string h3c_release_info;
    GetH3CInfo(h3c_release_info);
    if (!h3c_release_info.empty())
        return h3c_release_info;

    //try find os release info from /etc/
    std::string osnameversion = GetComputerName();
    osnameversion += " ";
    osnameversion += GetComputerVersion();
    if (osnameversion != "") return osnameversion;

    //try get os release from uname
    struct utsname name;
    ::bzero(&name, sizeof(name));

    std::string release_version;
    if(::uname(&name) == -1)
        return release_version;
    release_version.append(name.sysname);
    release_version.append(" ");
    release_version.append(name.nodename);
    release_version.append(" ");
    release_version.append(name.release);
    release_version.append(" ");
    release_version.append(name.version);
    release_version.append(" ");
    release_version.append(name.machine);
    return release_version;
}

void CPcInfoLinux::GetH3CInfo(std::string& info) {
    std::string file = "/etc/h3c_cas_cvk-version";
    if (!file_utils::IsExist(file))
        return;
    FILE* fstream = fopen(file.c_str(), "r");
    char buffer[1024];
    if (fstream && fgets(buffer, sizeof(buffer) - 1, fstream)) {
        std::string content = std::string(buffer);
        size_t index = content.find('\n');
        if (index != std::string::npos)
            content.erase(index, 1);

        if (content.empty()) {
            fclose(fstream);
            return;
        }

        info = std::string("H3C ") + content;
    }
    fclose(fstream);
    return;
}

bool CPcInfoLinux::GetReleaseFileList(std::vector<std::string> &need_search_files) {
    need_search_files.push_back("/etc/issue");
    DIR* dp;
    if ((dp = opendir("/etc/")) == NULL) {
        LOG_ERROR("open dir[%s] failed, because %s.", strerror(errno));
        return false;
    }
    std::string search_dir = "/etc/";
    struct dirent* result = NULL;
    while ((result = readdir(dp)) != NULL) {
        do {
            if (strcmp(result->d_name, ".") == 0 || (strcmp(result->d_name, "..") == 0)) {
                break;
            }
            if (std::string(result->d_name).find("-release") != std::string::npos) {
                need_search_files.push_back(std::string("/etc/") + std::string(result->d_name));
            }
        } while(false);

    }

    if (NULL != dp) closedir(dp);
    return true;
}

bool CPcInfoLinux::SortReleaseFileList(std::vector<std::string> &need_search_files) {
    for (std::size_t idx = 0; idx < need_search_files.size(); idx++) {
        if (idx != 0 && need_search_files[idx] == std::string("/etc/lsb-release")) {
            need_search_files[idx] = need_search_files[0];
            need_search_files[0] = std::string("/etc/lsb-release");
        } else if (need_search_files[idx] == std::string("/etc/os-release")) {
            if (need_search_files[0] == std::string("/etc/lsb-release")) {
                need_search_files[idx] = need_search_files[1];
                need_search_files[1] = std::string("/etc/os-release");
            } else {
                std::size_t jdx;
                for (jdx = idx + 1; jdx < need_search_files.size(); jdx++) {
                    if (need_search_files[jdx] == std::string("/etc/os-release")) {
                        need_search_files[idx] = need_search_files[1];
                        need_search_files[1] = std::string("/etc/os-release");
                        break;
                    }
                }
                if (jdx == need_search_files.size()) {
                    need_search_files[idx] = need_search_files[0];
                    need_search_files[0] = std::string("/etc/os-release");
                }
            }
        }
    }
    return true;
}

void CPcInfoLinux::GetOSNameVersion() {
    std::string Local_Os_name = std::string("red:ubuntu:suse:centos:mandriva:debian:gentoo:slackware:");
    Local_Os_name += std::string("knoppix:mepis:xrandros:freebsd:amazon:xenserver:");
    Local_Os_name += std::string("neokylin:kylin:isoft:nfs:deepin");
    std::vector<std::string>local_os_vets;
    string_utils::Split(local_os_vets, Local_Os_name, ":");
    std::vector<std::string> need_search_files;
    if (false == GetReleaseFileList(need_search_files) || false == SortReleaseFileList(need_search_files)) {
        LOG_ERROR("get computer info with release files failed, get release file list failed.");
        return;
    }
    char buffer[1024];
    std::string uploadname = "";
    // common method to get computer name and os version
    for(std::size_t idx = 0; idx < need_search_files.size(); idx++) {
        FILE* fstream = fopen(need_search_files[idx].c_str(), "r");
        //lsb-release need to singlely handle
        bool ok1 = false, ok2 = false;
        if (need_search_files[idx] == std::string("/etc/lsb-release")) {
            while (fstream && NULL != fgets(buffer, sizeof(buffer), fstream)) {
                std::vector<std::string> contents_vets;
                string_utils::Split(contents_vets, std::string(buffer), "=");
                if (contents_vets.size() > 1 && contents_vets[0] == "DISTRIB_ID") {
                    uploadname = string_utils::ToLower(contents_vets[1]);
                    std::map<std::string, std::string>::iterator it;
                    it = m_osmaps_.find(uploadname);
                    if(it != m_osmaps_.end()) {
                        m_computer_name_ = it->second;
                    } else {
                        m_computer_name_ = uploadname;
                    }
                    ok1 = true;
                }
                if(contents_vets.size() > 1 && contents_vets[0] == "DISTRIB_RELEASE") {
                    m_computer_version_ = string_utils::ToLower(contents_vets[1]);
                    ok2 = true;
                }
            }
        } else {
            while (fstream && NULL != fgets(buffer, sizeof(buffer), fstream)) {
                std::vector<std::string> contents_vets;
                string_utils::Split(contents_vets, std::string(buffer), "=");
                if (contents_vets.size() > 1 && contents_vets[0] == "NAME") {
                    uploadname = string_utils::ToLower(contents_vets[1]);
                    std::map<std::string, std::string>::iterator it = m_osmaps_.begin();
                    while (it != m_osmaps_.end()) {
                        if ((it->first == "kylin" && uploadname == it->first) || (it->first != "kylin" && uploadname.find(it->first) != std::string::npos)) {
                            m_computer_name_ = it->second;
                            break;
                        } else {
                            it++;
                        }
                    }
                    if (it == m_osmaps_.end())
                        m_computer_name_ = uploadname;
                    ok1 = true;
                }
                if (contents_vets.size() > 1 && contents_vets[0] == "VERSION") {
                    m_computer_version_ = string_utils::ToLower(contents_vets[1]);
                    ok2 = true;
                }
            }
        }
        if(fstream) {
            fclose(fstream);
            fstream = NULL;
        }
        if(ok1 && ok2) {
            return;
        }
    }
    // special method to get computer name and os version
    for(std::size_t idx = 0; idx < need_search_files.size(); idx++) {
        FILE* fstream = fopen(need_search_files[idx].c_str(), "r");
        //lsb-release need to singlely handle
        while (fstream && NULL != fgets(buffer, sizeof(buffer), fstream)) {
            std::string tmp = std::string(buffer);
            std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::tolower);
            for (std::size_t ldx = 0; ldx < local_os_vets.size(); ldx++) {
                if (tmp.find(local_os_vets[ldx]) != std::string::npos) {
                    uploadname = local_os_vets[ldx];
                    std::map<std::string, std::string>::iterator it;
                    it = m_osmaps_.find(uploadname);
                    if (it != m_osmaps_.end()) {
                        m_computer_name_ = it->second;
                    } else {
                        m_computer_name_ = uploadname;
                        size_t index = m_computer_name_.find('\n');
                        if (index != std::string::npos)
                            m_computer_name_.erase(index, 1);
                    }
                    std::vector<std::string> version_vets;
                    string_utils::Split(version_vets, tmp, " ");
                    bool isNky = (m_computer_name_ == "中标麒麟" || m_computer_name_ == "Neokylin" || m_computer_name_ == "neokylin");
                    for (std::size_t vdx = 0; vdx < version_vets.size(); vdx++) {
                        bool findversion = false;
                        if (isNky) {
                            version_vets[vdx].erase(0, version_vets[vdx].find_first_not_of(' '));
                            if (version_vets[vdx].size() > 2 &&
                                version_vets[vdx][0] == 'v' &&
                                version_vets[vdx][1] >= '0' &&
                                version_vets[vdx][1] <= '9')
                                findversion = true;
                        } else {
                            std::vector<std::string> tmp_vet;
                            string_utils::Split(tmp_vet, version_vets[vdx], ".");
                            if (tmp_vet.size() > 0) {
                                std::stringstream ss;
                                int num;
                                ss << tmp_vet[0];
                                if (ss >> num)
                                    findversion = true;
                            }
                        }

                        if (findversion) {
                            m_computer_version_ = version_vets[vdx];
                            size_t index = m_computer_version_.find('\n');
                            if (index != std::string::npos)
                                m_computer_version_.erase(index, 1);

                            fclose(fstream);
                            return;
                        }
                    }
                }
            }
        }
        if(fstream) {
            fclose(fstream);
            fstream = NULL;
        }
    }
}

void CPcInfoLinux::InitOSMap() {
    m_osmaps_.insert(std::make_pair("red", "RedHat"));
    m_osmaps_.insert(std::make_pair("ubuntu", "Ubuntu"));
    m_osmaps_.insert(std::make_pair("suse", "SuSe"));
    m_osmaps_.insert(std::make_pair("centos", "CentOS"));
    m_osmaps_.insert(std::make_pair("mandriva", "Mandriva"));
    m_osmaps_.insert(std::make_pair("debian", "Debian"));
    m_osmaps_.insert(std::make_pair("gentoo", "Gentoo"));
    m_osmaps_.insert(std::make_pair("slackware", "Slackware"));
    m_osmaps_.insert(std::make_pair("knoppix", "Knoppix"));
    m_osmaps_.insert(std::make_pair("mepis", "Mepis"));
    m_osmaps_.insert(std::make_pair("xrandros", "Xrandros"));
    m_osmaps_.insert(std::make_pair("freebsd", "FreeBSD"));
    m_osmaps_.insert(std::make_pair("amazon", "Amazon Linux AMI"));
    m_osmaps_.insert(std::make_pair("xenserver", "XenServer"));
    m_osmaps_.insert(std::make_pair("neokylin", "中标麒麟"));
    m_osmaps_.insert(std::make_pair("中标麒麟", "中标麒麟"));
    m_osmaps_.insert(std::make_pair("kylin", "银河麒麟"));
    m_osmaps_.insert(std::make_pair("银河麒麟", "银河麒麟"));
    m_osmaps_.insert(std::make_pair("nfs", "中科方德"));
    m_osmaps_.insert(std::make_pair("方德", "中科方德"));
    m_osmaps_.insert(std::make_pair("isoft", "普华"));
    m_osmaps_.insert(std::make_pair("普华", "普华"));
    m_osmaps_.insert(std::make_pair("deepin", "深度"));
    m_osmaps_.insert(std::make_pair("深度", "深度"));
}