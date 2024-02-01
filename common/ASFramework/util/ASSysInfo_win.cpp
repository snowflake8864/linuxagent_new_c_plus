#include "stdafx.h"
#include "ASSysInfo.h"

#include <windows.h>

#include <Psapi.h>
#include <Tlhelp32.h>
#include <UserEnv.h>
#include <MMSystem.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib,"Userenv.lib")

int EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable)
{
	int nResult = FALSE;
	int nRetCode = FALSE;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tkp = { 0 };

	do 
	{
		nRetCode = ::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		if (!nRetCode)
			break;

		nRetCode = ::LookupPrivilegeValue(NULL, lpszPrivilegeName, &tkp.Privileges[0].Luid);
		if (!nRetCode)
			break;

		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		nRetCode = ::AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
		if (!nRetCode)
			break;

		nResult = TRUE;
	} while (FALSE);

	if (hToken != NULL)
	{
		CloseHandle(hToken);
	}

	return nResult;
}

void FileTimeToTime_t(FILETIME& ft,__time64_t& tm)  
{  
	ULARGE_INTEGER ui;  
	ui.LowPart  =  ft.dwLowDateTime;  
	ui.HighPart =  ft.dwHighDateTime;  
	tm =  ((LONGLONG)(ui.QuadPart - 116444736000000000) / 10000000);  
}  

BOOL DosPathToNtPath( LPTSTR pszDosPath, LPTSTR pszNtPath )
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//检查参数
	if(!pszDosPath || !pszNtPath )
		return FALSE;

	//获取本地磁盘字符串
	if(GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for(i = 0; szDriveStr[i]; i += 4)
		{
			if(!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if(!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if(_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}			
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

BOOL GetProcessFullPath( DWORD dwPID, TCHAR* pszFullPath)
{
	TCHAR       szImagePath[MAX_PATH];  
	HANDLE      hProcess;  

	if(!pszFullPath)  
		return FALSE;  

	pszFullPath[0] = '\0';  
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);  
	if(!hProcess)  
		return FALSE;  

	if(!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))  
	{  
		CloseHandle(hProcess);  
		return FALSE;  
	}  

	if(!DosPathToNtPath(szImagePath, pszFullPath))  
	{  
		CloseHandle(hProcess);  
		return FALSE;  
	}  

	CloseHandle(hProcess);  

	return TRUE;  
}

HANDLE FindProcess(LPCTSTR lpcszName, LPCTSTR lpcszFullName, BOOL bCheckFullName, BOOL bNeedTerminate,BOOL bCheckParent,DWORD dwParentID)
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);

	HANDLE hProcessTaget = NULL;
	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);   
	if(hSnapshot == (HANDLE)-1) 
		return hProcessTaget;

	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);
	DWORD dwDesiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
	if (bNeedTerminate)
		dwDesiredAccess |= PROCESS_TERMINATE | SYNCHRONIZE;

	BOOL bMore = ::Process32First(hSnapshot,&pe);
	while(bMore)
	{   
		if(_tcsicmp(lpcszName, pe.szExeFile) == 0)
		{
			if(bCheckParent && pe.th32ParentProcessID != dwParentID)
			{
				bMore = ::Process32Next(hSnapshot,&pe);   
				continue;
			}

			TCHAR szFullpath[1024] = {0};
			HANDLE hProcess = NULL;
			if (hProcess = ::OpenProcess(dwDesiredAccess, FALSE, pe.th32ProcessID))
			{
				if (bCheckFullName)
				{
					TCHAR szLongPath[MAX_PATH] = {};

					::GetModuleFileNameEx(hProcess, NULL, szFullpath, _countof(szFullpath) - 1);
					if (0 == wcslen(szFullpath))
					{
						GetProcessFullPath(pe.th32ProcessID,szFullpath);
					}

					GetLongPathName(szFullpath, szLongPath, MAX_PATH);
					if(_tcsicmp(lpcszFullName, szFullpath) == 0)
					{
						hProcessTaget = hProcess;
						break;
					}
					else if (_tcsicmp(lpcszFullName, szLongPath) == 0)
					{
						hProcessTaget = hProcess;
						break;
					}

					::CloseHandle(hProcess);
				}
				else
				{
					hProcessTaget = hProcess;
					break;
				}
			}
			else
			{
			}
		}
		bMore = ::Process32Next(hSnapshot,&pe);   
	}

	::CloseHandle(hSnapshot);
	return hProcessTaget;
}

__int64 CASSysInfo::GetSysStartTime()
{
	TCHAR szPath[MAX_PATH] = {0}; 
	GetSystemDirectory(szPath,MAX_PATH);
	PathCombine(szPath,szPath,L"winlogon.exe");

	HANDLE handle = FindProcess(_T("winlogon.exe"),szPath,true,false,false,0);
	if(!handle)
	{
		wstring strFullPath = szPath;
		strFullPath = L"\\??\\" + strFullPath;

		handle = FindProcess(_T("winlogon.exe"),strFullPath.c_str(),true,false,false,0);

		if(!handle)
		{
			LOG_ERROR("open process %s fail, lasterr[%d],GetSysStartTime fail",strFullPath.c_str(),GetLastError());
			return 0;
		}
	}

	__time64_t tTime = 0;
	FILETIME ftCreate = {0}, ftExit = {0}, ftKernel = {0}, ftUser = {0};
	if(GetProcessTimes(handle, &ftCreate, &ftExit, &ftKernel, &ftUser))
	{
		FileTimeToTime_t(ftCreate,tTime);
	}

	CloseHandle(handle);
	return tTime;
}

__int64 CASSysInfo::GetSysStartSeconds()
{
	DWORD dwStartSeconds = ::timeGetTime();
	dwStartSeconds = dwStartSeconds / 1000;
	return dwStartSeconds;
}