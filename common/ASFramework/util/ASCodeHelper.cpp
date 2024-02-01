#include "stdafx.h"
#include "ASCodeHelper.h"

namespace ASCodeHelper
{

	std::string ConvertFromUTF8ByCodePage(const char* lpszData)
	{
#if (defined _WINDOWS) || (defined WIN32)
		std::string strReturn;
		char* szAnsi = NULL;
		wchar_t* wszString = NULL;
		do 
		{
			CPINFOEX info;
			if(!GetCPInfoEx(CP_ACP, 0, &info)) break;
			int wcsLen = ::MultiByteToWideChar(CP_UTF8, NULL, lpszData, -1, NULL, 0);  
			wszString = new wchar_t[wcsLen];
			if(!wszString) break;
			::MultiByteToWideChar(CP_UTF8, NULL, lpszData, -1, wszString, wcsLen);

			int ansiLen = ::WideCharToMultiByte(info.CodePage, NULL, wszString, -1, NULL, 0, NULL, NULL);
			szAnsi = new char[ansiLen];  
			if(!szAnsi) break;

			::WideCharToMultiByte(info.CodePage, NULL, wszString, -1, szAnsi, ansiLen, NULL, NULL);  
			strReturn = szAnsi;
		} while (false);

		if(szAnsi)delete szAnsi;
		if(wszString) delete wszString;

		return strReturn;
#else
		return lpszData;
#endif

	}

	std::string ConvertToUTF8ByCodePage(const char* lpszData)
	{
#if (defined _WINDOWS) || (defined WIN32)
		std::string strReturn;
		char* szUtf8 = NULL;
		wchar_t* wszString = NULL;
		do 
		{
			CPINFOEX info;
			if(!GetCPInfoEx(CP_ACP, 0, &info)) break;
			int wcsLen = ::MultiByteToWideChar(info.CodePage, NULL, lpszData, -1, NULL, 0);  
			wszString = new wchar_t[wcsLen];
			if(!wszString) break;
			::MultiByteToWideChar(info.CodePage, NULL, lpszData, -1, wszString, wcsLen);

			int ansiLen = ::WideCharToMultiByte(CP_UTF8, NULL, wszString, -1, NULL, 0, NULL, NULL);
			szUtf8 = new char[ansiLen];  
			if(!szUtf8) break;

			::WideCharToMultiByte(CP_UTF8, NULL, wszString, -1, szUtf8, ansiLen, NULL, NULL);  
			strReturn = szUtf8;
		} while (false);

		if(szUtf8)delete szUtf8;
		if(wszString) delete wszString;

		return strReturn;
#else
		return lpszData;
#endif
	}
}