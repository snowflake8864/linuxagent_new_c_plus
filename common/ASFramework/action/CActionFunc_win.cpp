#include "stdafx.h"
#include "CActionFunc.h"
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include "OSChecker.h"

int CActionFunc::GetPEFileVer(const char* pchFile, long& lHight, long& lLow)
{
	long dwVerSize;
	DWORD dwHandle;

	char  szVersionBuffer[1024 * 16] = { 0 };
	char szVer[1024] = { 0 };
#ifdef _WINDOWS
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
	long dwHight = 0;
	long dwLow = 0;

	if (!GetPEFileVer(pchFile, dwHight, dwLow))
		return false;

	char chVer[126] = {0};
	_snprintf( chVer, 126-1, "%d.%d.%d.%d",HIWORD(dwHight), LOWORD(dwHight), HIWORD(dwLow), LOWORD(dwLow));
	strVer = chVer;

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
			LOG_ERROR("�������� %s ��ȡʱrevert�ض���ʧ��",strParam);
		return (string)CW2A(str.GetBuffer(), CP_UTF8);
	}
	else
	{
		LOG_ERROR("�������� %s ��ȡʱ�ر��ض���ʧ��",strParam);
		return "";
	}
#endif
}

int CActionFunc::GetRealPath(string strDir, string &strPath, bool bPath, bool bCloseRedirect)
{
	// support var:%osecsafe%, %appdata%, and so on.  shoud x64 system path
	if(!strPath.length())
		return 0;
	if(bPath)
	{
		if( -1 == strPath.find('%'))
			strPath = strDir + strPath;
		else
		{
			int nPos1 = strPath.find('%');
			int nPos2 = strPath.find('%', nPos1 + 1);
			int nPos = strPath.find("%osecsafe%");
			if(nPos1 >= nPos2)
			{
				LOG_ERROR("���������е� % ��ƥ�䣬%s ",strPath.c_str());
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
						LOG_ERROR("�������� %s ��ȡʧ�ܣ����ô��� %s ",strEnv.c_str(), strPath.c_str());
						return 2;
					}
					strPath = strLeft + strEnvValue + strRelative;
					LOG_DEBUG("�������� %s ��ȡ�ɹ�%s���ϲ���·�� %s ",strEnv.c_str(), strEnvValue.c_str(), strPath.c_str());
				}
			}
		}
	}
	else
	{
		// param �Կո�ָ�: /S /D=%%\xxxxxx /p=xxxx 
		std::list<string> strParamList;
		boost::algorithm::split(strParamList,strPath, boost::is_any_of(" "));
		string strNewParam;
		for(std::list<string>::iterator it = strParamList.begin(); it != strParamList.end(); ++it)
		{
			string strParam = *it, strTmp;
			if( -1 != strParam.find('%'))
			{
				int nPos1 = strParam.find('%');
				int nPos2 = strParam.find('%', nPos1 + 1);
				int nPos = strParam.find("%osecsafe%");
				if(nPos1 >= nPos2)
				{
					LOG_ERROR("���������е� % ��ƥ�䣬%s ",strPath.c_str());
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
							LOG_ERROR("�������� %s ��ȡʧ�ܣ����ô��� %s ",strEnv.c_str(), strPath.c_str());
							return 2;
						}
						strTmp = strLeft + strEnvValue + strRelative;
						LOG_DEBUG("�������� %s ��ȡ�ɹ�%s���ϲ���·�� %s ",strEnv.c_str(), strEnvValue.c_str(), strTmp.c_str());
					}
					strNewParam = strNewParam + strTmp + " ";
				}
			}
			else
				strNewParam = strNewParam + strParam + " ";
		}
		strPath = strNewParam;
	}
	LOG_DEBUG("�ϲ���·�� %s ", strPath.c_str());

	return 0;
}

bool CActionFunc::EntSafeCopyFile(const char* src, const char* dst)
{
	bool ok = false;
	string strDst(dst);
#ifdef _WINDOWS
	for(int i=0;i< 10;i++)
	{
		BOOL del_old = FALSE;
		// ���֧�ֹ���ɾ�����Ϳ��Ը�������ʱ����ֱ��ɾ����ֱ��ɾ�����޷�����
		del_old = ::DeleteFileA(string(strDst + ".del").c_str());
		if(::PathFileExistsA(dst))
		{
			// ����ļ����򿪣���ر�ʱϵͳ��ɾ��
			del_old = ::MoveFileA(dst, string(strDst + ".del").c_str());
			del_old = ::DeleteFileA(string(strDst + ".del").c_str());
			if(!del_old)
				MoveFileExA(string(strDst + ".del").c_str(), NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
			del_old = ::DeleteFileA(dst);
			if(!del_old)
				MoveFileExA(dst, NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
		}

		ok = ::CopyFileA(src, dst, false);
		if(ok) break;

		Sleep(100);
	}
#endif

	return ok;
}

bool CActionFunc::SafeMoveFile(const char* src, const char* dst, long max_wait_second)
{
	bool ok = false;
	for(int i=0;i<(10*max_wait_second) + 1;i++)
	{
		bool del_old = false;
		string strDest = dst;
		// ���֧�ֹ���ɾ�����Ϳ��Ը�������ʱ����ֱ��ɾ����ֱ��ɾ�����޷�����
		del_old = ::DeleteFileA(string(strDest + ".del").c_str());
		if(::PathFileExistsA(dst))
		{
			// ����ļ����򿪣���ر�ʱϵͳ��ɾ��
			del_old = ::MoveFileA(dst, string(strDest + ".del").c_str());
			del_old = ::DeleteFileA(string(strDest + ".del").c_str());
			if(!del_old)
				MoveFileExA(string(strDest + ".del").c_str(), NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
			del_old = ::DeleteFileA(dst);
			if(!del_old)
				MoveFileExA(dst, NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
		}

		ok = ::MoveFileA(src, dst);
		if(ok) break;

		Sleep(100);
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
	boost::algorithm::split(strL, strList, boost::is_any_of(","));
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