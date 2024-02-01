#include "stdafx.h"
#include "TlHelp32.h"
#include "ASProcUtil.h"

#include <windows.h>

int CASProcUtil::GetCurPid()
{
	return GetCurrentProcessId();
}

int CASProcUtil::GetCurTid()
{
	return GetCurrentThreadId();
}

std::string CASProcUtil::GetCurProcessFullPath()
{
	char szFullPath[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szFullPath, MAX_PATH);
	return szFullPath;
}

bool CASProcUtil::Is64BitProcess()
{
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 
	LPFN_ISWOW64PROCESS fnIsWow64Process = NULL; 
	BOOL bIsWow64 = false; 

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandleA("kernel32"),"IsWow64Process"); 
	if (NULL != fnIsWow64Process) 
	{ 
		fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
	} 
	return bIsWow64;
}

std::string CASProcUtil::GetCurProcessName()
{
	char szFullPath[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szFullPath, MAX_PATH);

	char* p = strrchr(szFullPath, '\\');
	assert(p != NULL);
	if (!p)	return "";
	return std::string(p+1,szFullPath+strlen(szFullPath));
}

ASCode CASProcUtil::CreateChildProcess(const char* lpszExecPath,const char* lpszCmdLine,long long* pChildId,int* pErrCode)
{
	assert(lpszExecPath && strlen(lpszExecPath) > 0);
	if(!(lpszExecPath && strlen(lpszExecPath) > 0))
		return ASErr_INVALIDARG;

	SHELLEXECUTEINFOA ShellExecInfo = {0};
	ShellExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShellExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShellExecInfo.lpVerb = "open";
	ShellExecInfo.nShow = SW_SHOWNORMAL;
	ShellExecInfo.hInstApp = NULL;
	ShellExecInfo.lpFile = lpszExecPath;   
	ShellExecInfo.lpParameters = lpszCmdLine ? lpszCmdLine : "";
	if(!ShellExecuteExA(&ShellExecInfo) || !ShellExecInfo.hProcess)
	{
		if(pErrCode) *pErrCode = GetLastError();
		return ASErr_FAIL;
	}
	else
	{
		if(pChildId) *pChildId = (__int64)(ShellExecInfo.hProcess);
		return ASErr_OK;
	}
}

void CASProcUtil::CloseProcHandleOrId(__int64 nHandleOrId)
{
	if(nHandleOrId) CloseHandle((HANDLE)nHandleOrId);
}

bool CASProcUtil::IsProcessActive(__int64 nHandleOrId)
{
	if (nHandleOrId)
	{
		DWORD retCode = STILL_ACTIVE;
		GetExitCodeProcess((HANDLE)nHandleOrId,&retCode);
		if (retCode == STILL_ACTIVE)
		{
			return true;
		}
	}
	return false;
}

ASCode CASProcUtil::GetCurProcessCmdline(std::vector<std::string>& cmdLst)
{
	int nArgs = 0;
	LPWSTR* pArgs = CommandLineToArgvW(GetCommandLineW(),&nArgs);
	if(pArgs && nArgs > 0)
	{
		for(int i = 1; i < nArgs; ++i)
		{
			if(wcslen(pArgs[i]) > 0)
			{
				std::string strTmp = CW2A(pArgs[i],CP_UTF8);
				cmdLst.push_back(strTmp);
			}
		}
	}

	return ASErr_OK;
}

bool CASProcUtil::IsProcessActiveByPid(unsigned long ulPid)
{
	bool bActive = false;
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;

	// Take a snapshot of all processes in the system.
	hProcessSnap = ::CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( INVALID_HANDLE_VALUE==hProcessSnap )
		return false;


	// Set the size of the structure before using it.
	PROCESSENTRY32 pe32 = {0};
	pe32.dwSize = sizeof( PROCESSENTRY32 );	

	BOOL bContinue = ::Process32First( hProcessSnap, &pe32 );
	while( bContinue )
	{
		if(pe32.th32ProcessID==ulPid) {bActive = true; break;}
		bContinue = ::Process32Next( hProcessSnap, &pe32 );
	}

	if (INVALID_HANDLE_VALUE!=hProcessSnap)
		::CloseHandle( hProcessSnap );

	return bActive;
}