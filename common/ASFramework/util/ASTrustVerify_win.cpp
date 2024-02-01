#include "stdafx.h"
#include "ASTrustVerify.h"
#include "CStrCvt.h"

#include <windows.h>
#include <wincrypt.h>
#include <mscat.h>
#include <wintrust.h>
#include <SoftPub.h>

#pragma comment (lib, "wintrust")

BOOL CheckMSSignature(LPCWSTR lpFileName)
{
	BOOL bRet = FALSE;
	HCATADMIN hCatAdmin = NULL;
	if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
		return FALSE;

	HANDLE hFile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return FALSE;
	}

	DWORD dwCnt = 100;
	BYTE byHash[100];
	CryptCATAdminCalcHashFromFileHandle(hFile, &dwCnt, byHash, 0);
	CloseHandle(hFile);

	LPWSTR pszMemberTag = new WCHAR[dwCnt * 2 + 1];
	for (DWORD dw = 0; dw < dwCnt; ++dw)
	{
		wsprintfW(&pszMemberTag[dw * 2], L"%02X", byHash[dw]);
	}

	WINTRUST_DATA wd = { 0 };
	WINTRUST_FILE_INFO wfi = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };
	CATALOG_INFO ci = { 0 };
	HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, byHash, dwCnt, 0, NULL);
	if (NULL == hCatInfo)
	{
		wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
		wfi.pcwszFilePath = lpFileName;
		wfi.hFile = NULL;
		wfi.pgKnownSubject = NULL;

		wd.cbStruct = sizeof(WINTRUST_DATA);
		wd.dwUnionChoice = WTD_CHOICE_FILE;
		wd.pFile = &wfi;
		wd.dwUIChoice = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wd.dwStateAction = WTD_STATEACTION_IGNORE;
		wd.dwProvFlags = WTD_SAFER_FLAG;
		wd.hWVTStateData = NULL;
		wd.pwszURLReference = NULL;
	}
	else
	{
		CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0);
		wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
		wci.pcwszCatalogFilePath = ci.wszCatalogFile;
		wci.pcwszMemberFilePath = lpFileName;
		wci.pcwszMemberTag = pszMemberTag;

		wd.cbStruct = sizeof(WINTRUST_DATA);
		wd.dwUnionChoice = WTD_CHOICE_CATALOG;
		wd.pCatalog = &wci;
		wd.dwUIChoice = WTD_UI_NONE;
		wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
		wd.dwProvFlags = 0;
		wd.hWVTStateData = NULL;
		wd.pwszURLReference = NULL;
	}

	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	HRESULT hr = WinVerifyTrust(NULL, &action, &wd);
	bRet = SUCCEEDED(hr);

	if (NULL != hCatInfo)
		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

	CryptCATAdminReleaseContext(hCatAdmin, 0);
	delete[] pszMemberTag;
	return bRet;
}

bool CASTrustVerify::IsTrustedFile(const char* lpszFile)
{
	if (!lpszFile || strlen(lpszFile) <= 0 || !PathFileExistsA(lpszFile))
		return false;

#if (defined _WINDOWS) || (defined WIN32)
	std::wstring strPathW = CA2T(lpszFile);
#else
	std::wstring strPathW = CVT_S2WS(lpszFile,"UTF-8");
#endif

	if (Check360Sign(strPathW.c_str()))
		return true;

	if (CheckMSSignature(strPathW.c_str()))
		return true;

	return false;
}

bool CASTrustVerify::Is360SignedFile(const char* lpszFile)
{
	if (!lpszFile || strlen(lpszFile) <= 0 || !PathFileExistsA(lpszFile))
		return false;

#if (defined _WINDOWS) || (defined WIN32)
	std::wstring strPathW = CA2T(lpszFile);
#else
	std::wstring strPathW = CVT_S2WS(lpszFile,"UTF-8");
#endif

	if (Check360Sign(strPathW.c_str()))
		return true;
	else
		return false;
}