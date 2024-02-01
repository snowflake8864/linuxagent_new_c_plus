#include "performance.h"
#include <time.h>
#include <cstring>
#include "common/log/log.h"
#include <stdlib.h>
#include <errno.h>
#include <cstdio>
#include <sys/sysinfo.h>
#include <time.h>


std::string CPerformance::getboottime() {
	struct sysinfo info;
    time_t cur_time = 0;
    time_t boot_time = 0;
    struct tm *ptm = NULL;
    if (sysinfo(&info)) {
   		return "";
    }
    time(&cur_time);
    if (cur_time > info.uptime) {
    boot_time = cur_time - info.uptime;
    }
    else {
    boot_time = info.uptime - cur_time;
    }
    ptm = gmtime(&boot_time);
	char buff_time[255] = {0};
	memset(buff_time, 0, 255);
	sprintf(buff_time, "%d", (int)boot_time);

    //printf("System boot time: %d-%-d-%d %d:%d:%d\n", ptm->tm_year + 1900,
      //  ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
   return buff_time; 

}

void CPerformance::getCpuInfo(double &nCpuPercent, long &nCpuTime){
	CpuInfo *cpuInfo = new CpuInfo();
	cpuInfo->setCalcFrequency(5);
	cpuInfo->getCpuInfo(&nCpuPercent);
	delete cpuInfo;

    time_t t = time(NULL);
	struct tm now_time;
    now_time = *localtime(&t);
    nCpuTime = mktime(&now_time);
}

unsigned long CPerformance::getMemInfo(){
	MemInfo *memInfo = new MemInfo();
	unsigned long total_mem,mem_used;
	memInfo->_getMemUseState(total_mem,mem_used );
	delete memInfo;
	return total_mem;
}

int CPerformance::getDiskInfo(){
	//printf("CPerformance::getDiskInfo run.\n");
	long total_disk = 0;
	FILE *fd_total = NULL;
	char buff[256] = {0};
	char name[128] = {0};
	int ma = 0, mi = 0;
	long long sz = 0;
	fd_total = std::fopen ("/proc/partitions", "r");
	if (fd_total == NULL) {
		printf("CPerformance getting Disk info, failed to open the file. file:(/proc/partition), err:(%s)\n"
				, std::strerror(errno));
		return -1;
	}
	while (fgets(buff,sizeof(buff),fd_total) != NULL) {
		if (strstr(buff,"sda") != NULL) {
			std::sscanf (buff, "%u %u %u %[^\n]",(unsigned int*)&ma, (unsigned int*)&mi, (unsigned int*)&sz, name);
			total_disk = sz;
			break;
		}
		bzero(buff,sizeof(buff));
		bzero(name,sizeof(name));

	}
	std::fclose(fd_total);
	//printf("CPerformance::getDiskInfo: total disk: %ld KB, %ld M\n", total_disk, total_disk/1024);

	char other[256] = {0};
	long used = 0, total_used = 0, total=0;
	FILE* fd_free = NULL;
	fd_free = popen ("df -l", "r");
	if (fd_free == NULL) {
        printf("CPerformance getting Disk info, failed to open the file. cmd:(df -l), err:(%s)\n"
                , std::strerror(errno));
		return -1;
	}
	int count = 0;
	while (fgets(buff,sizeof(buff),fd_free) != NULL) {
		count ++;
		if(count == 1|| strstr(buff,"tmpfs") != NULL || strstr(buff, "none") != NULL || strstr(buff, "udev") != NULL)
			continue;

		std::sscanf (buff, "%s %u %u %[^\n]",name, (unsigned int*)&total, (unsigned int*)&used, other);
		total_used += used;
		bzero(buff,sizeof(buff));
		bzero(name,sizeof(name));
		bzero(other,sizeof(other));

	}
	pclose(fd_free);
	return total_used/1024/1024;
}
