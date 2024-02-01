#include <cstdio>
#include <errno.h>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/statvfs.h>
#include "cpuinfo.h"
#include "common/log/log.h"

CpuUseState::CpuUseState():
	user(0),nice(0),
	system(0),idle(0)
{
	::bzero(name,sizeof(name));
}

CpuUseState::CpuUseState(const CpuUseState& cpu_use)
{
	::memcpy(name,cpu_use.name,sizeof(name));
	user = cpu_use.user;
	nice = cpu_use.nice;
	system = cpu_use.system;
	idle = cpu_use.idle;
}
CpuInfo::CpuInfo()
	:_cpu_use(0.0),
	m_iCalcFrequency(0){
		_getCpuUseState(_last);
	}

int CpuInfo::_getCpuUseState(CpuUseState& cpu_use)
{
	FILE *fd = NULL;
	char buff[256] = {0};

	fd = std::fopen ("/proc/stat", "r");
	if (fd == NULL) {
		printf("CpuInfo getting CPU usage state, failed to open the file. file:(/proc/stat), err:(%s)\n"
				, std::strerror(errno));
		return -1;
	}

	{
		char* ignore = std::fgets(buff, sizeof(buff), fd);
		(void)ignore;
	}

    std::sscanf(buff, "%s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", \
    cpu_use.name, &cpu_use.user, &cpu_use.nice, &cpu_use.system, &cpu_use.idle, &cpu_use.iowait, \
    &cpu_use.irq, &cpu_use.softirq, &cpu_use.steal, &cpu_use.guest, &cpu_use.guest_nice); 


	std::fclose(fd);

	return 0;
}

double CpuInfo::_calcCpuUseState(const CpuUseState& o,const CpuUseState& n)
{
	unsigned long long od, nd;
	//unsigned int id, sd, nid;
    unsigned long long id, sd;
	double cpu_use = 0.0;

	od = (unsigned long long) (o.user + o.nice + o.system +o.idle);//第一次(用户+优先级+系统+空闲)的时间再赋给od
	nd = (unsigned long long) (n.user + n.nice + n.system +n.idle);//第二次(用户+优先级+系统+空闲)的时间再赋给od

	id = (unsigned long long) (n.user - o.user);    //用户第一次和第二次的时间之差再赋给id
	sd = (unsigned long long) (n.system - o.system);//系统第一次和第二次的时间之差再赋给sd
	if ((nd-od) != 0) {
		cpu_use = (double)((sd+id)*10000.0)/(nd-od); //((用户+系统)x10000)除(第一次和第二次的时间差)再赋给g_cpu_used
		//cpu_use = 10000.0 * (sd+id)/(nd-od); //((用户+系统)x10000)除(第一次和第二次的时间差)再赋给g_cpu_used
	} else {
		cpu_use = 0.0;
	}
    // LOG_INFO("CPU usage: %.2f%%\n", cpu_use);  
	return cpu_use;
}

void CpuInfo::setCalcFrequency(int iCalcFrequency) {
	m_iCalcFrequency = iCalcFrequency;
}

void CpuInfo::getCpuInfo(double *nCpuPercent) {
	if (m_iCalcFrequency <= 0) {
		m_iCalcFrequency = 5;
	}
	sleep(m_iCalcFrequency);

	CpuUseState now_use;

	int rc = _getCpuUseState(now_use);
	if (rc == -1) {
        //获取CPU使用信息，无法获取CPU陈述
		printf("CpuInfo getting CPU info, Unable to get CUP state.\n");
		*nCpuPercent = 0;
		return;
	}

	double now_cpu_use = _calcCpuUseState(_last,now_use);
	_cpu_use = now_cpu_use;
	double cpu_use_percent = _cpu_use  / 100.0;
     //LOG_INFO("===CPU usage: %.2f%%\n", cpu_use_percent);  
	*nCpuPercent = cpu_use_percent;
}

double CpuInfo::getUsage() 
{  
    FILE *fd = NULL;
    char buff[256] = {0};

    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;  
    char cpu[5];  
    fd = std::fopen ("/proc/stat", "r");
    if (fd == NULL) {
        printf("CpuInfo getting CPU usage state, failed to open the file. file:(/proc/stat), err:(%s)\n"
                , std::strerror(errno));
        return -1;
    }

    {
        char* ignore = std::fgets(buff, sizeof(buff), fd);
        (void)ignore;
    }

    std::sscanf(buff, "%s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", \
            cpu, &user, &nice, &system, &idle, &iowait, \
            &irq, &softirq, &steal, &guest, &guest_nice); 


    std::fclose(fd);

    unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal;
    unsigned long long idle_time = idle + iowait;
    double usage = 100.0 * (total - idle_time) / total;
    //LOG_INFO("CPU usage: %.2f%%\n", usage);  
    return usage;  
}  

#include "common/utils/string_utils.hpp"
std::string getCpuNum() {
	char buf[16] = {0};
	int ret = 0;
	FILE* fp = popen("cat /proc/cpuinfo |grep processor|wc -l", "r");
	if(fp) {
		ret = fread(buf, 1, sizeof(buf)-1, fp);
		pclose(fp);
	}
	if (buf[strlen(buf)] == '\n') {
		buf[strlen(buf)] = '\0';
	}

	if (buf[strlen(buf)-1] == '\n') {
		buf[strlen(buf)-1] = '\0';
	}
	return buf;
}


int getDiskInfo(double &totoal, double &usedPercent) {
	//printf("CPerformance::getDiskInfo run.\n");
	struct statvfs fsinfo;
    if (statvfs("/", &fsinfo) == -1)
    {
        printf("Failed to get file system information\n");
        return -1;
    }
	totoal = fsinfo.f_blocks * fsinfo.f_frsize / 1024 / 1024;
	double usedSize = totoal - (fsinfo.f_bfree * fsinfo.f_frsize / 1024 / 1024);
	usedPercent = usedSize *100 /totoal;
	return 0;
}
