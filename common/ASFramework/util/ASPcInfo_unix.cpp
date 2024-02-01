#include "stdafx.h"
#include "ASPcInfo.h"

std::string CASPcInfo::GetComputerName()
{
	char szHostName[256] = {0};
	::gethostname(szHostName,sizeof(szHostName)-1);
	return szHostName;
}

std::string CASPcInfo::GetOSDetail()
{
#ifdef __linux__
	return "Linux";
#endif
	return "Mac";
}
