#include "backend/net_agent/policy_recv.h"
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <fstream>
#include <iostream>
#include "common/json/cJSON.h"
#include "common/uuid.h"
#include "common/log/log.h"
#include "common/utils/net_utils.h"
#include "common/ini_parser.h"
#include "common/socket_client/ISocketClientMgr.h"
#include "osec_common/socket_osec.h"
#include "osec_common/osec_pathmanager.h"
#include "osec_common/global_message.h"
#include "osec_common/osec_socket_utils.h"
#include "osec_common/global_config.hpp"
#include "backend/net_agent/net_status.h"
#include "backend/net_agent/ent_client_net_agent.h"
#include "backend/net_agent/data_operation/parse_json.h"
#include "backend/net_agent/data_operation/build_json.h"
#include "common/pcinfo/pc_base_info.h"
#include "common/utils/string_utils.hpp"
#include "common/md5sum.h"
#include "performance.h"
#include "cpuinfo.h"

#define GETCLIENTTASK_API  "v1/gettask"
#define GETCLIENTAUTH_API  "v1/auth"

#define JSON_SETTING_SERVER_IP              "ServerIP"

bool CPolicyRecvWorker::Run() {
    int ret = QH_THREAD::CThread::run(NULL);
    if (ret != 0) {
        LOG_ERROR("start policy thread error, ret = %d", ret);
        return false;       
    } else {
        LOG_INFO("start policy thread success");
        return true;
    }
}

static bool localIsIPv6 = false;
static bool isIPv6(const std::string& ip) {  
    return ip.find('.') == std::string::npos;  
}

std::string CPolicyRecvWorker::GetServerAddrInfo() {
    std::string strIP;
    std::string strPort;
    CNETSTATUS->GetServerIPPORT(strIP, strPort);
    localIsIPv6 = isIPv6(strIP);
    return strIP + ":" + strPort;
}

static  int getLocalIPMac(std::string &ip, std::string &mac)
{
    struct ifaddrs * ifAddrStruct=NULL;
    void * tmpAddrPtr=NULL;
    struct ifaddrs * iter = NULL;
    getifaddrs(&ifAddrStruct);
    if (ifAddrStruct) {
        iter = ifAddrStruct;
    }
    std::string network_name = "";
    while (ifAddrStruct!=NULL) {

        if (!localIsIPv6 &&ifAddrStruct->ifa_addr->sa_family==AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            if (strcmp(addressBuffer, "127.0.0.1")) {
                //ip += addressBuffer;
                network_name = ifAddrStruct->ifa_name;
                LOG_INFO("%s IP Address %s, flag:%d\n", ifAddrStruct->ifa_name, addressBuffer, ifAddrStruct->ifa_flags); 
                break;
            }
        } else if (localIsIPv6 && ifAddrStruct->ifa_addr->sa_family==AF_INET6) { // check it is IP6
            // is a valid IP6 Address
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifAddrStruct->ifa_addr)->sin6_addr, addressBuffer, INET6_ADDRSTRLEN);  

            if (strncmp(addressBuffer, "fe80:",5) == 0) {
                //ip += addressBuffer;
                network_name = ifAddrStruct->ifa_name;
                LOG_INFO("%s IP Address %s, flag:%d\n", ifAddrStruct->ifa_name, addressBuffer, ifAddrStruct->ifa_flags); 
                break;
            }
        } 
        ifAddrStruct=ifAddrStruct->ifa_next;
    }

    if(ifAddrStruct) {
        freeifaddrs(iter);
    }
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in6 *sa;
	int family, s;
    //char addr[INET6_ADDRSTRLEN] = {0};
    char addr[NI_MAXHOST] = {0};
    getifaddrs (&ifap);
    if (ifap) {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

            std::string temp_netname = ifa->ifa_name;
			family = ifa->ifa_addr->sa_family;  
			if (/*temp_netname == network_name && */(family == AF_INET || family == AF_INET6)) {
				s = getnameinfo(ifa->ifa_addr,
						(family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
						addr, sizeof(addr),
						NULL, 0, NI_NUMERICHOST);
				if (family == AF_INET6 && (strncmp(addr, "fe80", 4) == 0 || strncmp(addr, "::1", 3) == 0)) {
					continue;
				}
				if (family == AF_INET && strncmp(addr, "127.0.0.1", 9) == 0) {
					continue;
				}
				if (!ip.empty())
					ip += ",";
				ip += addr;
			}

#if 0
            if (ifa->ifa_addr->sa_family==AF_INET6) {
                sa = (struct sockaddr_in6 *) ifa->ifa_addr;
                getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), addr,
                            sizeof(addr), NULL, 0, NI_NUMERICHOST);
                std::string temp_netname = ifa->ifa_name;
                if (temp_netname == network_name) {
                    if (strncmp(addr, "fe80", 4) != 0) {
                        ip += addr;
						if (ifa->ifa_next)
							ip += ",";
                    }
                    //break;
                }
            } else if (ifa->ifa_addr->sa_family == AF_INET){

				tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
				char addressBuffer[INET_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
				if (strcmp(addressBuffer, "127.0.0.1")) {
					ip += addressBuffer;
					if (ifa->ifa_next)
						ip += ",";
					//break;
				}

			}
#endif
        }
    }
    if (ifap) {
        freeifaddrs(ifap);
    }

    do {
        int    sockfd;
        struct ifreq        ifr;
        char buff_mac[20] = {0};
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("socket error");
            mac = "";
            break;
        }
        strcpy(ifr.ifr_name, network_name.c_str());      //Interface name
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) { 
            sprintf(buff_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0], 
            (unsigned char)ifr.ifr_hwaddr.sa_data[1], 
            (unsigned char)ifr.ifr_hwaddr.sa_data[2], 
            (unsigned char)ifr.ifr_hwaddr.sa_data[3], 
            (unsigned char)ifr.ifr_hwaddr.sa_data[4], 
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
        }
        mac =  buff_mac;
        LOG_INFO("mac:%s\n", mac.c_str());
		LOG_INFO("==mac[%s], ip[%s]\n", mac.c_str(), ip.c_str());
        close(sockfd);
    } while (false);
    return 0;
}
void trim(char *str) {
    int start = 0;
    int end = strlen(str) - 1;

    // Find the first non-space character
    while (isspace(str[start])) {
        start++;
    }

    // Find the last non-space character
    while (end >= start && isspace(str[end])) {
        end--;
    }

    // Shift the characters to the left
    int i;
    for (i = start; i <= end; i++) {
        str[i - start] = str[i];
    }

    // Add the null terminator
    str[i - start] = '\0';
}


#if 0
int getIPaddr(std::string &ip, std::string &mac) 
{
#define MAX_BUFFER_SIZE 256
	FILE *fp;
	char buffer[MAX_BUFFER_SIZE]={0};
	char ip_str[MAX_BUFFER_SIZE]={0};
	char mac_str[MAX_BUFFER_SIZE]={0};

	// 执行命令并读取输出
	//fp = popen("ifconfig | awk '/inet (?!127\\.0\\.0\\.1)([0-9]{1,3}\\.){3}[0-9]{1,3}/ {ip=$2} /ether/ {mac=$2} END {print ip, mac}'", "r");
	fp = popen("ifconfig | grep -oP 'inet (?!127\.0\.0\.1)([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | head -1", "r");
	if (fp == NULL) {
		printf("无法执行命令\n");
		return 1;
	}

	// 读取输出并提取 IP 地址和 MAC 地址
	fgets(buffer, sizeof(buffer), fp);
	sscanf(buffer, "%s", ip_str);
	ip = ip_str;
	// 输出结果
	// 关闭文件指针
	pclose(fp);

	// 执行命令并读取输出
	//fp = popen("ifconfig | awk '/inet (?!127\\.0\\.0\\.1)([0-9]{1,3}\\.){3}[0-9]{1,3}/ {ip=$2} /ether/ {mac=$2} END {print ip, mac}'", "r");
	fp = popen("ifconfig | awk '/ether/ {print $2; exit}' | head -1", "r");
	if (fp == NULL) {
		printf("无法执行命令\n");
		return 1;
	}

	// 读取输出并提取 IP 地址和 MAC 地址
	memset(buffer, 0, sizeof(buffer));
	fgets(buffer, sizeof(buffer), fp);
	sscanf(buffer, "%s", mac_str);
	mac = mac_str;
	// 输出结果
	// 关闭文件指针
	pclose(fp);



	LOG_INFO("=======IP addr: %s\n", ip.c_str());
	LOG_INFO("=========MAC addr: %s\n", mac.c_str());

}
#else
int getIPaddr(std::string &ip, std::string &mac) 
{
#define MAX_LINE_LENGTH 512
	FILE *fp;
	char line[MAX_LINE_LENGTH];
	char *ip_address = NULL, *mac_start = NULL;
	char mac_address[18];
	int need_get_mac = 1;
	fp = popen("ifconfig", "r");
	if (fp == NULL) {
		printf("Failed to run command\n");
		exit(1);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\n")] = '\0';  // Remove trailing newline character
		trim(line);

		if (need_get_mac == 1) {
			mac_start = strstr(line, "HWaddr ");
			if (mac_start != NULL) {
				mac_start += 7; // 跳过 "HWaddr" 字符串
				strncpy(mac_address, mac_start, 17);
				mac_address[17] = '\0';
				need_get_mac = 0;
				mac = mac_address;
				LOG_INFO("mac[%s]\n", mac_address);
				continue;
			}
		}

		if (need_get_mac == 1 && strncmp(line, "ether ", 6) == 0) {
			mac_start = strtok(line + 6, " ");
			mac = mac_start;
			need_get_mac = 0;
		} else if (strncmp(line, "inet addr:", 10) == 0) {
			ip_address = strtok(line + 10, " ");
			if (strncmp(ip_address, "127.0.0.1", 9) != 0) {
				if (!ip.empty())
					ip += ",";
				ip += ip_address;
			}
		} else if (strncmp(line, "inet6 addr:", 11) == 0) {
			ip_address = strtok(line + 11, " ");
			if (strncmp(ip_address, "fe80", 4) != 0 && strncmp(ip_address, "::1", 3) != 0) {
				char *slash_pos = strchr(ip_address, '/');
				if (slash_pos != NULL) {
					*slash_pos = '\0';
				}

				if (!ip.empty())
					ip += ",";
				ip += ip_address;
			}
		} else if (strncmp(line, "inet ", 5) == 0) {
			ip_address = strtok(line + 5, " ");
			if (strncmp(ip_address, "127.0.0.1", 9) != 0) {
				if (!ip.empty())
					ip += ",";
				ip += ip_address;
			}
		} else if (strncmp(line, "inet6 ", 6) == 0) {
			ip_address = strtok(line + 6, " ");
			if (strncmp(ip_address, "fe80", 4) != 0 && strncmp(ip_address, "::1", 3) != 0) {
				char *slash_pos = strchr(ip_address, '/');
				if (slash_pos != NULL) {
					*slash_pos = '\0';
				}
				if (!ip.empty())
					ip += ",";
				ip += ip_address;
			}
		}
	}

	// Close the pipe and print the IP addresses
	pclose(fp);
	LOG_INFO("=======IP addr:%s\n", ip.c_str());
	LOG_INFO("=========MAC addr:%s\n", mac.c_str());
}
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 256

int isValidNetInfo(const std::string &filename)
{
    const char* expectedPrefix = "https://";
    char line[MAX_LINE_LENGTH];
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



bool CPolicyRecvWorker::Init(CEntClientNetAgent* pNetAgent, RUN_TASK_CALL task) {
    m_callFun = task;
    m_pNetAgent = pNetAgent;
    INIParser parser_ver;
    std::string net_info_path_ver = "/opt/osec/net_info_ver.ini"; 
    std::string version = "";
    if(!parser_ver.ReadINI(net_info_path_ver)) {
        LOG_ERROR("Init:parse net info path[%s] failed.", net_info_path_ver.c_str());
    } else {
        version = parser_ver.GetValue(SECTION_SERVERINFO, KEY_VERSION);
    }
    m_baseinfo.ver = version;

    INIParser parser;
    std::string net_info_path = "/opt/osec/net_info.ini";
    if (file_utils::IsExist(net_info_path)) {
        if (isValidNetInfo(net_info_path) == 1) {
            if(!parser.ReadINI(net_info_path)) {
                LOG_ERROR("Init:parse net info path[%s] failed.", net_info_path.c_str());
                return 0;
            }
        } else {
            file_utils::CopyFile("/var/log/net_info.ini", "/opt/osec/net_info.ini");
            LOG_INFO("cp /var/log/net_info.ini /opt/osec \n");
            if (isValidNetInfo(net_info_path) == 1) {
                if(!parser.ReadINI(net_info_path)) {
                    LOG_ERROR("Init:parse net info path[%s] failed.", net_info_path.c_str());
                    return 0;
                }
            }
        }
    } else {
        file_utils::CopyFile("/var/log/net_info.ini", "/opt/osec/net_info.ini");
        LOG_INFO("cp /var/log/net_info.ini /opt/osec \n");
        if (isValidNetInfo(net_info_path) == 1) {
            if(!parser.ReadINI(net_info_path)) {
                LOG_ERROR("Init:parse net info path[%s] failed.", net_info_path.c_str());
                return 0;
            }
        }

    }
    m_baseinfo.userid = parser.GetValue(SECTION_SERVERINFO, KEY_USER_ID);;
    CPerformance  perform;
    std::string str_server_addr = GetServerAddrInfo();
    CPcInfoLinux pcinfo;
	if (m_baseinfo.ip.empty() || m_baseinfo.macid.empty()) {
		getLocalIPMac(m_baseinfo.ip, m_baseinfo.macid);
	}
	if (m_baseinfo.ip.empty() || m_baseinfo.macid.empty()) {
		getIPaddr(m_baseinfo.ip, m_baseinfo.macid); 
	}


    
    // std::string test_ipaddr;
    // size_t pos = str_server_addr.find("http://");
    // if (pos != std::string::npos) {
    //     test_ipaddr = str_server_addr.substr( pos + strlen("http://"));
    // } else {
    //     pos = str_server_addr.find("https://");
    //     if (pos != std::string::npos) {
    //        test_ipaddr = str_server_addr.substr( pos + strlen("https://"));
    //     } else {
    //         test_ipaddr = str_server_addr;
    //     }
    // }
    // LOG_INFO("test_ipaddr:%s", test_ipaddr.c_str());
    // m_baseinfo.ip = pcinfo.GetReportIp(str_server_addr);
    // m_baseinfo.macid = pcinfo.GetReportMac(str_server_addr);
    //LOG_INFO("str_server_addr:%s, ip:%s, mac:%s\n", str_server_addr.c_str(), m_baseinfo.ip.c_str(), m_baseinfo.macid.c_str());
    if (m_baseinfo.macid.find("00:00:00:00:00") != std::string::npos) {
        std::string str_cmd = "ifconfig |grep 'inet addr' |grep Bcast |awk -F ':' '{print $2}' |awk -F ' ' '{print $1}'";
        std::string str_buf;
        char buf[255] = {0};
        int ret = 0;
        FILE* fp = popen(str_cmd.c_str(), "r");
        if(fp) {
            ret = fread(buf, 1, sizeof(buf)-1, fp);
            pclose(fp);
        }
        str_buf = buf;
        if (!str_buf.empty()) {
            m_baseinfo.ip = str_buf;
        }
    }

    std::string mgs_guid;
    if (!file_utils::IsExist("/etc/.vedasystem")) {
        char messgae_uuid[UUID_LEN] = {0};
        if (uuid::UUID_ESUCCESS != uuid::uuid4_generate(messgae_uuid)) {
            LOG_ERROR("genreate uuid failed for uid");
            return false;
        }
        std::ofstream ofile;
        ofile.open("/etc/.vedasystem");
        ofile << messgae_uuid << std::endl;
        ofile.close();
        mgs_guid = messgae_uuid;
        //mgs_guid = md5sum::md5(mgs_guid.c_str());
    }
    mgs_guid = md5sum::md5file("/etc/.vedasystem");
    // else {
    //     int64_t buff_len = 1024;
    //     char buff_cont[1024] = {0};
    //     if (!file_utils::GetFileContent("/etc/.vedasystem", buff_len, buff_cont)) {
    //         mgs_guid = md5sum::md5(buff_cont);
    //     } else {
    //         mgs_guid = md5sum::md5(m_baseinfo.macid);
    //     }
    // }
    m_baseinfo.uid = mgs_guid;
    if (m_baseinfo.ver.empty()) {
        m_baseinfo.ver = "1.0.0.10";
    }

    m_baseinfo.type = 1;
    struct utsname testbuff;
    int fb = 0;
    {
        fb = uname(&testbuff);
        if (fb<0) {
            perror("uname");
            return 0;
        } else {
            printf(" sysname:%s\n nodename:%s\n release:%s\n version:%s\n machine:%s\n \n ",\
                        testbuff.sysname,\
                        testbuff.nodename,\
                        testbuff.release,\
                        testbuff.version,\
                        testbuff.machine);
        }
    }
    m_baseinfo.os = pcinfo.GetComputerName() + pcinfo.GetComputerVersion() + "_kernel:";
    std::string kernel_relase = testbuff.release;
    m_baseinfo.os += kernel_relase;
    unsigned long memsize = perform.getMemInfo();
    int memsize_G = 0;
    int memsize_M = 0;
    if (memsize > 1048576) {
        memsize_G = memsize/1048576;
        memsize_M = memsize%1048576;
        m_baseinfo.memsize = string_utils::ToString(memsize_G);
        if (memsize_M > 0) {
            m_baseinfo.memsize += ".";
            m_baseinfo.memsize += string_utils::ToString(memsize_M);
        }
        m_baseinfo.memsize += "G";
    } else {
        m_baseinfo.memsize = string_utils::ToString(memsize);
        m_baseinfo.memsize += "K";
    }
    m_baseinfo.cpu = getCpuNum();
    //m_baseinfo.hdsize = string_utils::ToString(perform.getDiskInfo());

    double totoal = 0.0, usedPercent = 0.0;
    getDiskInfo(totoal, usedPercent);
    if (totoal > 1024) {
        totoal /= 1024;
        m_baseinfo.hdsize = string_utils::ToString(totoal);
        m_baseinfo.hdsize += "GB";
    } else {
        m_baseinfo.hdsize = string_utils::ToString(totoal);
        m_baseinfo.hdsize += "MB";
    }

    m_baseinfo.astarttime = perform.getboottime();
    m_baseinfo.osstarttime = perform.getboottime();
    m_baseinfo.auth = "123123";
   
//test
    char buff_host[255] = {0};
    gethostname(buff_host, 255);
    LOG_DEBUG("host_name:%s", buff_host);
    m_baseinfo.host_name = buff_host;
     m_pNetAgent->m_deviceuid = m_baseinfo.uid;
    return true;
}

bool CPolicyRecvWorker::UnInit() {
    QH_THREAD::CThread::quit();
    QH_THREAD::CThread::join();
    m_callFun = NULL;
    return true;
}

void CPolicyRecvWorker::refreshPolicyInfo(const std::string& str_section, const std::string& str_key, int value) {
    std::string str_polhis_path = PathManager::GetPolicyDataPath();
    INIParser parser;
    if (!parser.ReadINI(str_polhis_path)) {
        LOG_ERROR("read policy history file[%s] into ini format error.", str_polhis_path.c_str());
        return;
    }
    std::string str_value = string_utils::ToString(value);
    parser.SetValue(str_section, str_key, str_value);
    parser.WriteINI(str_polhis_path);
}

void CPolicyRecvWorker::recvNewTask() {
    //LOG_INFO("start recv task.");
    std::string url;
    ///先判断上线
    if (( m_bOnline == false) || (m_baseinfo.macid == "00:00:00:00:00:00") ) {
        std::string strRevBuf;
        long lHttpCode = 0;
        std::string str_send = "";
        CNETSTATUS->GenServerUri(GETCLIENTAUTH_API, url);
		if (m_baseinfo.ip.empty() || m_baseinfo.macid.empty()) {
			getLocalIPMac(m_baseinfo.ip, m_baseinfo.macid);
		}
		if (m_baseinfo.ip.empty() || m_baseinfo.macid.empty()) {
			getIPaddr(m_baseinfo.ip, m_baseinfo.macid); 
		}
        build_json::BuildAuthOnlineJson(m_baseinfo, str_send);
        LOG_INFO("post, url:%s,data:%s \n", url.c_str(), str_send.c_str());
        //url = "https://192.168.16.81:443/v1/auth";
        bool ok = CNETSTATUS->PostDataUseURL(url, strRevBuf, (char*)str_send.c_str(), str_send.length(), lHttpCode);
        LOG_INFO("post on line HttpCode[%d] rtndata[%s] result [%s]\n", int(lHttpCode), strRevBuf.c_str(), (ok ? "SUCCESS" : "FAILED"));
        
        if (!ok || (strRevBuf.find("OK") == std::string::npos)) {
            LOG_INFO("..................................................\n");
            LOG_INFO("online failed\n");
            LOG_INFO("..................................................\n");
            m_pNetAgent->DoSetOnlineStatus(m_bOnline);
            return;
        }
        parse_json::ParaseOnlineJson(strRevBuf, m_strToken);
        m_bOnline =  true;
        m_pNetAgent->DoSetOnlineStatus(m_bOnline);
    }

    std::string strRevBuf;
    CNETSTATUS->GenServerUri(GETCLIENTTASK_API, url);
    long lHttpCode = 0;
    bool ok = CNETSTATUS->PostDataUseURL(m_strToken, url, strRevBuf, (char*)"", 0, lHttpCode);
    //LOG_INFO("get new task token[%s],url:[%s], HttpCode[%d] rtndata[%s] result [%s]", m_strToken.c_str(), url.c_str(), int(lHttpCode), strRevBuf.c_str(), (ok ? "SUCCESS" : "FAILED"));
    //if (ok && (strRevBuf.find("OK") != std::string::npos)) {
    if (ok) {
        parseRecvTask(strRevBuf);
    } else {
        m_bOnline = false;
        m_pNetAgent->DoSetOnlineStatus(m_bOnline);
    }
}

void CPolicyRecvWorker::parseRecvTask(const std::string& str_content) {
    TASK_BASE task_;
    int ret = parse_json::ParseAllTaskInfo(str_content, task_);
    if (ret != 0) {
        LOG_ERROR("parse_json::ParseAllTaskInfo error!");
        return;
    }
    std::list<TASK_TYPE>::iterator iter;
    for (iter = task_.lst_type.begin(); iter != task_.lst_type.end(); iter++) {
        LOG_INFO("parseRecvTask task list :%d\n",*iter);
        m_callFun(m_pNetAgent, (TASK_TYPE)*iter);
    }
}

void* CPolicyRecvWorker::thread_function(void* param) {
    LOG_INFO("Thread, policy recv thread start!\n");
    //sleep(5);
    doWaitOrQuit(-1);
    while(1) {
        // if (doWaitOrQuit(1))
        //     break;
        recvNewTask();
        sleep(m_sleep_time);
    }

    LOG_DEBUG("Thread, policy recv thread exit!");

    return NULL;
}
