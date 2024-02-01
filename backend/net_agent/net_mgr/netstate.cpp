#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "common/log/log.h"
#include "common/utils/string_utils.hpp"
#include "common/utils/file_utils.h"
#include "../procInfo.h"

#include "netstate.h"

typedef int CECode;
#define CE_ERROR_OK                 0                   // 成功
#define CE_ERROR_UNKNOWN            0x80000001          // 未知错误
#define CE_ERROR_NO_IMPL            0x80000002          // 接口未实现
#define CE_ERROR_NO_MEMORY          0x80000003          // 申请内存失败
#define CE_ERROR_OPEN_FILE          0x80000004          // 打开文件失败
#define CE_ERROR_DATA               0x80000005          // 数据异常
#define CE_ERROR_LIB_FUNC           0x80000006          // 系统接口返回失败
#define CE_ERROR_EXEC_CMD           0x80000007          // 执行shell命令失败


#define TCP_FILE_PATH "/proc/net/tcp"
#define TCP6_FILE_PATH "/proc/net/tcp6"
#define UDP_FILE_PATH "/proc/net/udp"
#define UDP6_FILE_PATH "/proc/net/udp6"

void CPortInfo::getportinfo(std::vector<PORT_BUSINESS_LIST> &vecPort)
{
	//LOG_INFO("CPortInfo::getportinfo run");
	std::vector< std::string > str_port;
	FILE *stream = NULL;
	char buf[512] = {0};
                                          
	std::string getinfo = "netstat -tnlp";
	stream = popen(getinfo.c_str(), "r");
	if (stream == NULL) {
        LOG_ERROR_SYS("CPortInfo getting port info, popen failed. cmd:(%s)", getinfo.c_str());
		return;
	} else {
	    while (fgets(buf, sizeof(buf), stream) != NULL) {
	        if (strstr(buf, "tcp") != NULL || strstr(buf, "udp") != NULL) {
				std::string temp = std::string(buf);
				LOG_DEBUG("CPortInfo::getportinfo: netstat info: %s", temp.c_str());
				str_port.push_back(temp);
				bzero(buf, sizeof(buf));
			} else {
				LOG_DEBUG("CPortInfo::getportinfo: continue: %s", buf);
				continue;				
			}
	    }
		pclose(stream);                        
	}

	LOG_DEBUG("CPortInfo::getportinfo start handle port info");
	PORT_BUSINESS_LIST port_info;
	std::vector< std::string >::iterator it = str_port.begin();
	for (;it!=str_port.end();it++) {
		port_info.nTime = time(NULL);
		std::string temp;
		if ((*it).length() > 0) {
			temp = (*it).substr(0, (*it).length()-1);
		} else {
			temp = *it;
		}
		std::vector<std::string> str_vector;
		string_utils::Split(str_vector, temp, " ");
		if (str_vector.size() <7) {
            LOG_ERROR_DEV("CPortInfo getting port info, netstat format error. error:(%s)", temp.c_str());
			continue;
        }
        

		std::string processName = str_vector[6];
        int idx = processName.rfind("socat");
        if (idx != -1) {
            //LOG_INFO("[%s]\n",processName.c_str());
            continue;
        }
		//端口协议
		std::string protocol = str_vector[0];
		std::string local = str_vector[3];
		std::string remote = str_vector[4];
		std::string status = str_vector[5];
		std::string process;
		if (str_vector.size() >= 7) {
			process = str_vector[6];
		}
		if (status != "LISTEN") {
			process = status;
			status = "--";
		}
		port_info.strProtocol = protocol;
		//本机IP和端口
		int pos = local.rfind(":");
		if (pos != -1) {
			std::string localip = local.substr(0,pos);
			std::string localport = local.substr(pos+1);
			port_info.strLocalIP = localip;
			port_info.nLocalPort = atoi(localport.c_str());
		}
		//远端IP和端口
		pos = remote.rfind(":");
		if (pos != -1) {
			std::string remoteip = remote.substr(0,pos);
			std::string remoteport = remote.substr(pos+1);
			port_info.strRemoteIP = remoteip;
			port_info.strRemotePort = remoteport;
		}
		//端口状态（只有LISTEN和空）
		port_info.status = status;
		//进程ID和路径
		pos = process.find("/");
		if (pos != -1) {
			std::string processid = process.substr(0,pos);
			port_info.nPID = atoi(processid.c_str());
			port_info.strProcessPath = ProcInfo::getExecFullFileName(port_info.nPID);
		} else {
			port_info.nPID = 0;
			port_info.strProcessPath = "--";
		}
		port_info.nTime = time(NULL);
		vecPort.push_back(port_info);
	}
}

CPortInfo *CPortInfo::m_pInstance = NULL;
CPortInfo *CPortInfo::getInstance()
{
    if (m_pInstance == NULL) {
        m_pInstance = new CPortInfo();
    }
    return m_pInstance;
}

void CPortInfo::updateNetstatInfo(void)
{
	//LOG_INFO("CPortInfo::getportinfo run");
	std::vector< std::string > str_port;
	FILE *stream = NULL;
	char buf[512] = {0};
                                          
	std::string getinfo = "netstat -tnlp";
	stream = popen(getinfo.c_str(), "r");
	if (stream == NULL) {
        LOG_ERROR_SYS("CPortInfo getting port info, popen failed. cmd:(%s)", getinfo.c_str());
		return;
	} else {
	    while (fgets(buf, sizeof(buf), stream) != NULL) {
	        if (strstr(buf, "tcp") != NULL) {
				std::string temp = std::string(buf);
				LOG_DEBUG("CPortInfo::getportinfo: netstat info: %s", temp.c_str());
				str_port.push_back(temp);
				bzero(buf, sizeof(buf));
			} else {
				LOG_DEBUG("CPortInfo::getportinfo: continue: %s", buf);
				continue;				
			}
	    }
		pclose(stream);                        
	}
    QH_THREAD::CMutexManualLocker lck(&netstat_map_locker_);
    lck.lock();
    netstat_map.clear();
    netstat_web_map.clear();
    lck.unlock();
	LOG_DEBUG("CPortInfo::getportinfo start handle port info");
	PORT_BUSINESS_LIST port_info;
	std::vector< std::string >::iterator it = str_port.begin();
	for (;it!=str_port.end();it++) {
		std::string temp;
		if ((*it).length() > 0) {
			temp = (*it).substr(0, (*it).length()-1);
		} else {
			temp = *it;
		}
		std::vector<std::string> str_vector;
		string_utils::Split(str_vector, temp, " ");
		if (str_vector.size() <7) {
            LOG_ERROR_DEV("CPortInfo getting port info, netstat format error. error:(%s)", temp.c_str());
			continue;
        }
        
#if 0
		std::string processName = str_vector[6];
        int idx = processName.rfind("socat");
        if (idx != -1) {
            //LOG_INFO("[%s]\n",processName.c_str());
            continue;
        }
#endif
		//端口协议
		std::string protocol = str_vector[0];
		std::string local = str_vector[3];
		std::string remote = str_vector[4];
		std::string status = str_vector[5];
		std::string process;
		if (str_vector.size() >= 7) {
			process = str_vector[6];
		}
		if (status != "LISTEN") {
			process = status;
			status = "--";
		}
		port_info.strProtocol = protocol;

		//本机IP和端口
		int pos = local.rfind(":");
		if (pos != -1) {
			std::string localip = local.substr(0,pos);
			std::string localport = local.substr(pos+1);
			port_info.strLocalIP = localip;
			port_info.nLocalPort = atoi(localport.c_str());
		}
		//远端IP和端口
		pos = remote.rfind(":");
		if (pos != -1) {
			std::string remoteip = remote.substr(0,pos);
			std::string remoteport = remote.substr(pos+1);
			port_info.strRemoteIP = remoteip;
			port_info.strRemotePort = remoteport;
		}
		//端口状态（只有LISTEN和空）
		port_info.status = status;
		//进程ID和路径
		pos = process.find("/");
		if (pos != -1) {
			std::string processid = process.substr(0,pos);
			port_info.nPID = atoi(processid.c_str());
			port_info.strProcessPath = ProcInfo::getExecFullFileName(port_info.nPID);
		} else {
			port_info.nPID = 0;
			port_info.strProcessPath = "--";
		}
        lck.lock();
        netstat_map[port_info.nLocalPort] = port_info;
        netstat_web_map[local] = port_info;
        lck.unlock();
//        LOG_INFO("11===netstat_map=%p, map port=%d\n", &netstat_map, port_info.nLocalPort);
        //LOG_INFO("22===netstat_web_map=%p, map port=%d\n", &netstat_web_map, port_info.nLocalPort);
	}
    //LOG_INFO("updateNetstatInfo, size=%d\n", netstat_map.size());
}

void CPortInfo::updateDnatInfo(void)
{
	//LOG_INFO("CPortInfo::getportinfo run");
	std::vector< std::string > str_port;
	FILE *stream = NULL;
	char buf[512] = {0};
                                          
	std::string getinfo = "iptables -t nat -L -n -v|grep DNAT|grep tcp";
	stream = popen(getinfo.c_str(), "r");
	if (stream == NULL) {
        LOG_ERROR_SYS("CPortInfo getting port info, popen failed. cmd:(%s)", getinfo.c_str());
		return;
	} else {
	    while (fgets(buf, sizeof(buf), stream) != NULL) {
				std::string temp = std::string(buf);
				LOG_DEBUG("CPortInfo::getportinfo: netstat info: %s", temp.c_str());
				str_port.push_back(temp);
				bzero(buf, sizeof(buf));
	    }
		pclose(stream);                        
	}
    QH_THREAD::CMutexManualLocker lck(&netstat_map_locker_);
	LOG_DEBUG("CPortInfo::getportinfo start handle port info");
	PORT_BUSINESS_LIST port_info;
	std::vector< std::string >::iterator it = str_port.begin();
	for (;it!=str_port.end();it++) {
		std::string temp;
		if ((*it).length() > 0) {
			temp = (*it).substr(0, (*it).length()-1);
		} else {
			temp = *it;
		}
		std::vector<std::string> str_vector;
		string_utils::Split(str_vector, temp, " ");
		if (str_vector.size() <11) {
            LOG_ERROR_DEV("CPortInfo getting port info, netstat format error. error:(%s)", temp.c_str());
			continue;
        }
        
		//端口协议
		std::string protocol = str_vector[9];
		std::string dnat = str_vector[10];
		int pos = dnat.rfind(":");

        if (pos != -1) {
            std::string  localport = dnat.substr(pos+1);
            port_info.nLocalPort = atoi(localport.c_str());
			port_info.nPID = 0;
			port_info.strProcessPath = "iptableDNAT";
            lck.lock();
            netstat_map[port_info.nLocalPort] = port_info;
            netstat_web_map[localport] = port_info;
            lck.unlock();
        }
        //LOG_INFO("11===netstat_map=%p, map port=%d\n", &netstat_map, port_info.nLocalPort);
	}
    //LOG_INFO("updateNetstatInfo, size=%d\n", netstat_map.size());
}

void CPortInfo::updateDockerInfo(void)
{
	//LOG_INFO("CPortInfo::getportinfo run");
	std::vector< std::string > str_port;
	FILE *stream = NULL;
	char buf[512] = {0};
    if (system("command -v docker >/dev/null 2>&1") != 0) {
        //LOG_INFO("docker command is not found!\n");
        return ;
    }


    std::string getinfo = "docker ps --format '{{.Ports}}' | awk -F '[ ,]+' '{for(i=1; i<=NF; i++) if($i ~ /^[0-9]+\\/tcp$/) print $i}' | awk -F '/' '{print $1}'";                          
	stream = popen(getinfo.c_str(), "r");
	if (stream == NULL) {
        LOG_ERROR_SYS("CPortInfo getting port info, popen failed. cmd:(%s)", getinfo.c_str());
		return;
	} else {
	    while (fgets(buf, sizeof(buf), stream) != NULL) {
				std::string temp = std::string(buf);
				LOG_INFO("CPortInfo::getportinfo: netstat info: [%s]", temp.c_str());
				str_port.push_back(temp);
				bzero(buf, sizeof(buf));
	    }
		pclose(stream);                        
	}
    QH_THREAD::CMutexManualLocker lck(&netstat_map_locker_);
	LOG_DEBUG("CPortInfo::getportinfo start handle port info");
	PORT_BUSINESS_LIST port_info;
	std::vector< std::string >::iterator it = str_port.begin();
	for (;it!=str_port.end();it++) {
		std::string temp;
		if ((*it).length() > 0) {
			temp = (*it).substr(0, (*it).length()-1);
		} else {
			temp = *it;
		}
		port_info.nLocalPort = atoi(temp.c_str());
		//port_info.nPID = -1;
        port_info.nPID = 0;
        port_info.strProcessPath = "dockerBusinessPort";
        lck.lock();
        netstat_map[port_info.nLocalPort] = port_info;
        netstat_web_map[temp] = port_info;
        lck.unlock();
        //LOG_INFO("==================docker business Port is %s\n",temp.c_str());
	}
    //LOG_INFO("updateDockerInfo, size=%d\n", netstat_map.size());
}

bool CPortInfo::getNetstatinfo(void)
{
    bool ok = false;
    if ((ok = ShouldUpdate())) {
        updateNetstatInfo(); // 
        updateDnatInfo();
        updateDockerInfo();
        last_access_clock = BACKEND_MGR->minutes_count;
    }
    return ok;
}

bool CPortInfo::getNetstatinfoImme(void)
{
    updateNetstatInfo(); // 
    updateDnatInfo();
    updateDockerInfo();
    last_access_clock = BACKEND_MGR->minutes_count;
    return true;
}

PORT_BUSINESS_LIST *CPortInfo::GetBusinessInfoByPort(int port)
{
    //LOG_INFO("===netstat_map=%p,port=%d\n", &netstat_map, port);
    QH_THREAD::CMutexAutoLocker lck(&netstat_map_locker_);
    std::map<int, PORT_BUSINESS_LIST >::iterator it = netstat_map.find(port);
    if (it != netstat_map.end()) {
        return &it->second;
    } else {
        return NULL;
    }
}

