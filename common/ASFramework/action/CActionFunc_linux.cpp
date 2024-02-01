#include "stdafx.h"
#include "CActionFunc.h"
#include "utils/file_utils.h"
#include "utils/string_utils.hpp"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include "OSChecker.h"

int CActionFunc::GetPEFileVer(const char* pchFile, long& lHight, long& lLow)
{
#ifdef _WINDOWS
	long dwVerSize;
	DWORD dwHandle;

	char  szVersionBuffer[1024 * 16] = { 0 };
	char szVer[1024] = { 0 };

	dwVerSize = GetFileVersionInfoSizeA(pchFile, &dwHandle);
	if( dwVerSize == 0 || dwVerSize > (sizeof(szVersionBuffer) - 1))
		return false;

	if(!GetFileVersionInfoA(pchFile, 0, dwVerSize, szVersionBuffer))
		return false;

	unsigned int nInfoLen = 0;
	VS_FIXEDFILEINFO* pInfo = NULL;

	if(!VerQueryValueA(szVersionBuffer, "\\", (void**)&pInfo, &nInfoLen))
		return FALSE;

	lHight = pInfo->dwFileVersionMS;
	lLow = pInfo->dwFileVersionLS;
#endif

	return true;
}

bool CActionFunc::GetPEFileVer(const char* pchFile, string& strVer)
{
#ifdef _WINDOWS
	long dwHight = 0;
	long dwLow = 0;

	if (!GetPEFileVer(pchFile, dwHight, dwLow))
		return false;

	char chVer[126] = {0};
	_snprintf( chVer, 126-1, "%d.%d.%d.%d",HIWORD(dwHight), LOWORD(dwHight), HIWORD(dwLow), LOWORD(dwLow));
	strVer = chVer;
#endif

	return true;
}

string CActionFunc::GetSystemDir(const char* strParam, bool bCloseRedirect)
{
#ifdef _WINDOWS
	if(!bCloseRedirect)
		return (string)CW2A(_wgetenv(CA2W(strParam, CP_UTF8)), CP_UTF8);

	if(COSChecker::DisableRedirect())
	{
		CString str = _wgetenv(CA2W(strParam, CP_UTF8));
		if ( !COSChecker::RestoreRedirect())
			LOG_ERROR("环境变量 %s 获取时revert重定向失败",strParam);
		return (string)CW2A(str.GetBuffer(), CP_UTF8);
	}
	else
	{
		LOG_ERROR("环境变量 %s 获取时关闭重定向失败",strParam);
		return "";
	}
#endif
	return "";
}

int CActionFunc::GetRealPath(string strDir, string &strPath, bool bPath, bool bCloseRedirect)
{
	// support var:%osec%, %appdata%, and so on.  shoud x64 system path
	if(!strPath.length())
		return 0;
	if(bPath)
	{
		if(std::string::npos == strPath.find('%'))
			strPath = strDir + strPath;
		else
		{
			int nPos1 = strPath.find('%');
			int nPos2 = strPath.find('%', nPos1 + 1);
			int nPos = strPath.find("%osec%");
			if(nPos1 >= nPos2)
			{
				LOG_ERROR("环境变量中的 % 不匹配，%s ",strPath.c_str());
				return 1;
			}
			else
			{
				string strRelative = strPath.substr(nPos2 + 2);
				string strLeft = strPath.substr(0, nPos1); // for param
				if(-1 != nPos)
				{
					strPath = strDir + strRelative;
					LOG_DEBUG("rela=%s, %s ", strRelative.c_str(),strPath.c_str());
				}
				else
				{
					string strEnv = strPath.substr(nPos1+1, nPos2-nPos1-1);
					string strEnvValue = GetSystemDir(strEnv.c_str(), bCloseRedirect);
					if(strEnvValue.empty())
					{
						LOG_ERROR("环境变量 %s 获取失败，配置错误 %s ",strEnv.c_str(), strPath.c_str());
						return 2;
					}
					strPath = strLeft + strEnvValue + strRelative;
					LOG_DEBUG("环境变量 %s 获取成功%s，合并后路径 %s ",strEnv.c_str(), strEnvValue.c_str(), strPath.c_str());
				}
			}
		}
	}
	else
	{
		// param 以空格分隔: /S /D=%%\xxxxxx /p=xxxx 
		std::list<string> strParamList;
		string_utils::Split(strParamList, strPath, " ");
		string strNewParam;
		for(std::list<string>::iterator it = strParamList.begin(); it != strParamList.end(); ++it)
		{
			string strParam = *it, strTmp;
			if(std::string::npos != strParam.find('%'))
			{
				int nPos1 = strParam.find('%');
				int nPos2 = strParam.find('%', nPos1 + 1);
				int nPos = strParam.find("%osec%");
				if(nPos1 >= nPos2)
				{
					LOG_ERROR("环境变量中的 % 不匹配，%s ",strPath.c_str());
					return 1;
				}
				else
				{
					string strRelative = strParam.substr(nPos2 + 2);
					string strLeft = strParam.substr(0, nPos1); // for param
					if(-1 != nPos)
					{
						strTmp = strLeft + strDir + strRelative;
					}
					else
					{
						string strEnv = strParam.substr(nPos1+1, nPos2-nPos1-1);
						string strEnvValue = GetSystemDir(strEnv.c_str(), bCloseRedirect);
						if(strEnvValue.empty())
						{
							LOG_ERROR("环境变量 %s 获取失败，配置错误 %s ",strEnv.c_str(), strPath.c_str());
							return 2;
						}
						strTmp = strLeft + strEnvValue + strRelative;
						LOG_DEBUG("环境变量 %s 获取成功%s，合并后路径 %s ",strEnv.c_str(), strEnvValue.c_str(), strTmp.c_str());
					}
					strNewParam = strNewParam + strTmp + " ";
				}
			}
			else
				strNewParam = strNewParam + strParam + " ";
		}
		strPath = strNewParam;
	}
	LOG_DEBUG("合并后路径 %s ", strPath.c_str());

	return 0;
}

bool CActionFunc::EntSafeCopyFile(const char* src, const char* dst)
{
	bool ok = false;
	struct stat st;
	int fin = ::open(src,O_RDONLY);
	if(fin == -1)
		return false;
	fstat(fin,&st);
	int fout = ::open(dst,O_CREAT | O_RDWR | O_TRUNC,st.st_mode);
	if(fout == -1)
	{
		::close(fin);
		return -1;
	}
	
	ssize_t size = 0;
	char buf[1024] = {0};
	while( (size = ::read(fin,buf,sizeof(buf))) > 0)
	{
		if(size != ::write(fout,buf,size))
		{
			ok = false;
			break;
		}
	}
	::close(fin);
	::close(fout);
	return ok;
}

bool CActionFunc::SafeMoveFile(const char* src, const char* dst, long max_wait_second)
{
	bool ok = false;
	for(int i=0;i<(max_wait_second) + 1;i++)
	{
		if(::rename(src,dst) == 0)
			ok = true;
		if(ok) break;
		sleep(1);
	}
	return ok;
}

bool CActionFunc::BInList(const char* file, const char* file_list)
{
	string strList = file_list;
	string strFile = file;
	if(strList.empty() || strFile.empty())
		return false;
	std::list<string> strL;
	string_utils::Split(strL, strList, ",");
	bool bFind = false;
	for (std::list<string>::iterator it = strL.begin(); it != strL.end(); it++)
	{
		if((string)*it == strFile)
		{
			bFind = true;
			break;
		}
	}
	strL.clear();
	return bFind;
}

bool CActionFunc::IsFileInFrameworkPath(string strFileFullPath,string strFrameWorkDir)
{
	if (strFileFullPath.empty() || strFrameWorkDir.empty())
	{
		return false;
	}
#ifdef _WINDOWS
	char tmp_buf[1024];
	GetFullPathNameA(strFileFullPath.c_str(),1024,tmp_buf,NULL);
	strFileFullPath = tmp_buf;
	int pos = strFileFullPath.rfind('\\');
	if (pos < 0)
	{
		return false;
	}
	string strPath = strFileFullPath.substr(0,pos);
	int len = strFrameWorkDir.size();
	if (strFrameWorkDir.at(len-1) == '\\')
	{
		strFrameWorkDir = strFrameWorkDir.substr(0,len-1);
	}
	std::transform(strPath.begin(), strPath.end(), strPath.begin(), ::tolower);
	std::transform(strFrameWorkDir.begin(), strFrameWorkDir.end(), strFrameWorkDir.begin(), ::tolower);
	if (strPath.compare(strFrameWorkDir) == 0)
	{
		return true;
	}
#endif
	return false;
};
