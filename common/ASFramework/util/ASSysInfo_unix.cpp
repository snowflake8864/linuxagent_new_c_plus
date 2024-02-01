#include "stdafx.h"
#include "ASSysInfo.h"
#include <sys/sysinfo.h>
#include <time.h>
#include <errno.h>

__int64 CASSysInfo::GetSysStartTime()
{
	__int64 lStartTime = GetSysStartSeconds();
	__int64 lTimeNow = time(NULL);
	if(lTimeNow > lStartTime)
		return lTimeNow - lStartTime;
	else
		return 0; 
}

__int64 CASSysInfo::GetSysStartSeconds()
{
	struct sysinfo info;
	if(sysinfo(&info))
	{
		LOG_ERROR("Failed to get sysinfo,error:%u,reason:%s",errno,strerror(errno));
		return 0;
	}
	return info.uptime;
	
}
