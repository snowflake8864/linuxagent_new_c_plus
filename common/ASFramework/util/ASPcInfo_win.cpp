#include "stdafx.h"
#include "ASPcInfo.h"

#include <comutil.h>
#include <Wbemidl.h>
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Winmm.lib")

bool CASPcInfo::IsOS64Bit()
{
	if (-1 != m_nOSBit)
		return 64 == m_nOSBit;

	boost::lock_guard<boost::mutex> lck(m_initLock);
	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	 
	HMODULE hKernel = GetModuleHandle(_T("kernel32"));
	LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hKernel, "IsWow64Process");
	if (!fnIsWow64Process)
		return false;

	BOOL bIsWow64 = FALSE;
	if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		return false;  		// handle error.default as false

	m_nOSBit = bIsWow64 ? 64 : 32;
	return bIsWow64 ? true : false;
}

std::string CASPcInfo::GetComputerName()
{
	static std::string s_strPCName;

	WCHAR wszPCName[MAX_PATH] = {0};
	DWORD dwPCNameLen = MAX_PATH - 1;
	::GetComputerNameW(wszPCName, &dwPCNameLen);

	s_strPCName = CW2A(wszPCName, CP_UTF8);

	return s_strPCName;
}

std::string CASPcInfo::GetOSDetail()
{
	static std::string s_strDetail;
	if(s_strDetail.length() > 0)
		return s_strDetail;

	HRESULT hres = E_FAIL;
	IWbemLocator *pLoc = NULL;
	IWbemServices* pSvc = NULL;
	IEnumWbemClassObject* pEnumClsObj = NULL;

	std::wstring strDetailW;
	do
	{
		CoInitialize(NULL);
		hres = CoCreateInstance(CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(LPVOID *) &pLoc);
		if (FAILED(hres) || !pLoc)
			break;

		hres = pLoc->ConnectServer(_bstr_t(L"root\\cimv2"),NULL,NULL,0,NULL,0,0,&pSvc);
		pLoc->Release(); 
		if (FAILED(hres) || !pSvc)
			break;

		hres = CoSetProxyBlanket(pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,NULL,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE);
		if (FAILED(hres))
			break;

		CString strQuery = L"SELECT * FROM Win32_OperatingSystem";
		hres = pSvc->ExecQuery(bstr_t("WQL"),bstr_t(strQuery),WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,NULL,&pEnumClsObj);   
		if (FAILED(hres) || !pEnumClsObj)
			break;

		while(1)
		{
			CComPtr<IWbemClassObject> pclsObj = NULL;      
			ULONG uReturn = 0;
			hres = pEnumClsObj->Next(WBEM_INFINITE,1,&pclsObj,&uReturn);
			if(uReturn == 0 || !pclsObj)
				break;

			CComVariant valDescription;
			if(FAILED(pclsObj->Get(L"Caption",0,&valDescription,NULL,NULL)) || valDescription.vt != VT_BSTR)
				continue;

			strDetailW = (WCHAR*)(valDescription.bstrVal);

			CComVariant valCSDVer;
			if(SUCCEEDED(pclsObj->Get(L"CSDVersion",0,&valCSDVer,NULL,NULL)) && valCSDVer.vt == VT_BSTR)
				strDetailW += valCSDVer.bstrVal;

			if(strDetailW.length() > 0)
			{
				s_strDetail = CW2A(strDetailW.c_str(),CP_UTF8);
			}

			break;
		}
	}while(FALSE);

	if(pSvc)		pSvc->Release();
	if(pEnumClsObj)	pEnumClsObj->Release();

	CoUninitialize();
	return s_strDetail;
}
