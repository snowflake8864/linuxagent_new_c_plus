#include "ASProcUtil.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>

int CASProcUtil::GetCurPid()
{
	return getpid();
}

int CASProcUtil::GetCurTid()
{
	return (int)syscall(224);
}

std::string CASProcUtil::GetCurProcessName()
{
	std::string strName = "360entclient";
	char strProcessPath[1024] = {0};
	
	do
	{
		if(readlink("/proc/self/exe", strProcessPath,1024) <=0) break;
		char *strProcessName = strrchr(strProcessPath, '/');
		if(strProcessName)strName = ++strProcessName;

	}while(false);
	
	return strName;
}

std::string CASProcUtil::GetCurProcessFullPath()
{
	std::string strInstallPath;
	char szTemp[1024] = {0};
	int nRet = readlink("/proc/self/exe", szTemp,1024);
	if(nRet > 0)
	{
		szTemp[nRet] = '\0';
		char* pLast = strrchr(szTemp,'/');
		if((pLast != NULL) && (pLast != szTemp))
		{
			szTemp[pLast - szTemp] = '\0';
		}
		
	}
	strInstallPath = szTemp;

	if (strInstallPath.empty())
		strInstallPath = "/opt/osec";

	strInstallPath.append("/");
	return strInstallPath;
}

bool CASProcUtil::IsProcessActive(long long nHandleOrId)
{
	if(kill(nHandleOrId,0)!=0)
		return true;
	else  	
		return false;
}

