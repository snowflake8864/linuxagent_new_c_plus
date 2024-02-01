#include "stdafx.h"
#include "ASSysInfo.h"
#include <time.h>
#include <sys/sysctl.h>
#include <errno.h>
__int64 CASSysInfo::GetSysStartTime()
{
	struct timeval boottime;
	size_t len = sizeof(boottime);
	int mib[2] = {CTL_KERN,KERN_BOOTTIME};
	if(sysctl(mib,2,&boottime,&len,NULL,0) < 0)
	{
		return 0;
	}
	return boottime.tv_sec;
}
__int64 CASSysInfo::GetSysStartSeconds()
{
	time_t csec = time(NULL);
	time_t bsec = GetSysStartTime();
	return difftime(csec,bsec);
}
