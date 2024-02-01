#include "stdafx.h"
#include "ASRunAction.h"
#include "CActionFunc.h"
#include "SystemternlHelper.h"

using namespace ASRunAction;

ASCode CASRunActionExe::Execute()
{
	LOG_TRACE("%s action ��ʼִ��, 3rd=%d",GetType(),m_b3rd);
	std::string strIsX64 = getBundleAString(this, AS_RUNACTION_KEY_X64, "0");
	if(strIsX64.compare("1") == 0 && !m_pcInfo.IsOS64Bit())
		return ASErr_OK;

	std::string strBaseDir = getBundleAString(this, AS_RUNACTION_ATTR_BASEDIR, "");
	std::string strRelativePath = getBundleAString(this, AS_RUNACTION_KEY_FILE, "");
	if(strBaseDir.length() <= 0 || strRelativePath.length() <= 0)
		return ASErr_FAIL;

	string strIfUpd = ASBundleHelper::getBundleAString(this,AS_ACTION_IF_UPDATE,"");
	string strUpdFiles = ASBundleHelper::getBundleAString(this,AS_MSGACTION_KEY_CONTENT,"");
	bool bIfupd = strIfUpd == "1" ? true : false;
	string strFileName = strRelativePath.substr(strRelativePath.rfind('\\') + 1);
	if(bIfupd && !CActionFunc::BInList(strFileName.c_str(), strUpdFiles.c_str()))
	{
		LOG_ERROR("ifupd configed, but the file is not in update file list��do not act��%s",strRelativePath.c_str());
		return ASErr_OK;
	}
	std::string strFullPath = strRelativePath;
	CActionFunc::GetRealPath(strBaseDir, strFullPath); 

	std::wstring strFullPathW = CA2W(strFullPath.c_str());
	std::string strParam = getBundleAString(this, ASRunAction::AS_RUNACTION_KEY_PARAM, "");
	std::string strWaitExit = getBundleAString(this, ASRunAction::AS_RUNACTION_KEY_WAITFOREXIT, "true");
	// strParam, file and verfile need to support var:%osecsafe%, %appdata%, and so on
	std::string strTry = getBundleAString(this,ASRunAction::AS_RUNACTION_TRY_COUNT,"1");
	string strVerFile = getBundleAString(this,ASRunAction::AS_RUNACTION_Ver_File,"");
	// wstring strVer = BundleHelper::getBundleString(this,RUNACTION_Ver,L"");
	wstring strCloseRedir = getBundleWString(this,ASRunAction::AS_RUNACTION_Disable_Wow64FsRedirection,L"");
	bool bCloseRedire = (0 == strCloseRedir.compare(L"true"));
	int nTry = atoi(strTry.c_str()) > 0 ? atoi(strTry.c_str()) : 1;
	bool bSuccess = true;
	string strRParam = strParam.c_str();
	if(0 != CActionFunc::GetRealPath(strBaseDir, strRParam, false, bCloseRedire))
	{
		return ASErr_FAIL;
	}
	wstring strRunInSystem = getBundleWString(this,ASRunAction::AS_RUNACTION_RUN_MODE,L"0"); // Ĭ�����û��˻�������������system�Ĳ���system

	if(!::PathFileExistsA(strFullPath.c_str()) || ( !m_b3rd && !CheckosecSign(strFullPathW.c_str())))
	{
		LOG_ERROR("[Exe]action,key[%s-%s] execute fail! file[%s] not exist or not trusted",strRelativePath.c_str(), strParam.c_str(),strFullPath.c_str());
		return ASErr_FAIL;
	}
	if (m_b3rd)
	{
		if (CActionFunc::IsFileInFrameworkPath(strFullPath,strBaseDir))
		{
			LOG_ERROR("3rd module [Exe]action,key[%s-%s] not execute! file is in osecsafe path!",strRelativePath.c_str(),strParam.c_str());
			return ASErr_OK;
		}
	}

	SHELLEXECUTEINFOA sei = {0};
	sei.cbSize = sizeof(SHELLEXECUTEINFO);
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;
	sei.hwnd = NULL;
	sei.lpVerb = NULL;
	sei.lpFile = strFullPath.c_str();
	sei.lpParameters = strRParam.c_str();
	sei.lpDirectory = NULL;
	sei.nShow = SW_HIDE;
	sei.hInstApp = NULL;
	do 
	{
		if(0 != strRunInSystem.compare(L"1"))
		{
			wstring strCmdLine = L"\"" + strFullPathW + L"\" ";
			strCmdLine += CA2W(strRParam.c_str());

			LOG_TRACEW(L"will start process in user, %s",strCmdLine.c_str());

			int nErrCode = 0;
			if(!SystemternlHelper::LaunchProcessAsUser((LPWSTR)strCmdLine.c_str(),nErrCode,&sei.hProcess) || !sei.hProcess)
			{
				LOG_ERROR("LaunchProcessAsUser fail��err %d-%d",nErrCode,GetLastError());
				return ASErr_FAIL;
			}
			//else // �û������Ȳ��ȣ������м��
			//	return S_OK;
		}
		else
		{
			if(!ShellExecuteExA(&sei))
			{
				LOG_ERROR("[Exe]action,key[%s-%s] execute fail! create process fail,lasterr[%d]", strRelativePath.c_str(), strParam.c_str(), GetLastError());
				return ASErr_FAIL;
			}
		}

		WaitForSingleObject(sei.hProcess,(strWaitExit == "true") ? 5 * 60 * 1000 : 30 * 1000); // ���ȴ�5����// WaitForSingleObject(sei.hProcess,(strWaitExit == "true") ? INFINITE : 30 * 1000);

		// check ver if VFile exists
		if(!m_strVer.length())
			break; // default sucess
		if(strVerFile.length() > 0)
		{
			string strRVer, strCheckFile = strVerFile;
			if(0 != CActionFunc::GetRealPath(strBaseDir, strCheckFile, true, bCloseRedire))
			{
				LOG_ERROR("%s action fail��ver check path %s config error",GetType(),strCheckFile.c_str());
				return ASErr_FAIL;
			}
			if(!CActionFunc::GetPEFileVer(strCheckFile.c_str(),strRVer) || strRVer != m_strVer)
			{
				LOG_ERROR("%s action��path %s fail�� ver verify fail, realver:%s != cfgVer:%s",GetType(),strRelativePath.c_str(),strRVer.c_str(), m_strVer.c_str());
				bSuccess = false;
			}
			else
				bSuccess = true;
		}
		if (bSuccess)
			break;
		nTry--;
		
	} while(nTry > 0);

	if(bSuccess)
	{
		LOG_TRACE("[Exe]action,key[%s-%s] execute successfully!", strRelativePath.c_str(), strParam.c_str());
	}
	else
	{
		LOG_TRACE("[Exe]action,key[%s-%s] execute failed!", strRelativePath.c_str(), strParam.c_str());
	}

	

	if(sei.hProcess)
		CloseHandle(sei.hProcess);

	if (bSuccess)
		return ASErr_OK;
	else
		return ASErr_FAIL;
}

ASCode CASRunActionSimpleDll::Execute()
{
	LOG_TRACE("%s action ��ʼִ��, 3rd=%d",GetType(),m_b3rd);
	std::string strIsX64 = getBundleAString(this, AS_RUNACTION_KEY_X64, "0");
	if (strIsX64.compare("1") == 0 && !m_pcInfo.IsOS64Bit())
		return ASErr_OK;

	std::string strBaseDir = getBundleAString(this, AS_RUNACTION_ATTR_BASEDIR, "");
	std::string strRelativePath = getBundleAString(this, AS_RUNACTION_KEY_FILE, "");
	if (strBaseDir.length() <= 0 || strRelativePath.length() <= 0)
		return ASErr_FAIL;

	std::string strFullPath = strRelativePath;
	CActionFunc::GetRealPath(strBaseDir, strFullPath); 

	std::wstring strFullPathW = CA2W(strFullPath.c_str());

	std::string strEntryFunc = getBundleAString(this, AS_RUNACTION_KEY_ENTRY, "");
	if (!::PathFileExistsA(strFullPath.c_str()) || (!m_b3rd && !CheckosecSign(strFullPathW.c_str())))
	{
		LOG_ERROR("[SimpleDll]action,key[%s-%s] execute fail! file[%s] not exist or not trusted", strRelativePath.c_str(), strEntryFunc.c_str(), strFullPath.c_str());
		return ASErr_FAIL;
	}
	if(strEntryFunc.length() <= 0)
	{
		LOG_ERROR("[SimpleDll]action,key[%s-%s] execute fail! no entry param!", strRelativePath.c_str(), strEntryFunc.c_str());
		return ASErr_FAIL;
	}

	HMODULE hModule = ::LoadLibrary(strFullPathW.c_str());
	if(!hModule)
	{
		LOG_ERROR("[SimpleDll]action,key[%s-%s] load fail!", strRelativePath.c_str(), strEntryFunc.c_str());
		return E_FAIL;
	}

	typedef VOID (__stdcall *PEXPORTFUNC)(VOID);

	PEXPORTFUNC pFunc = (PEXPORTFUNC)::GetProcAddress(hModule, strEntryFunc.c_str());
	if(!pFunc)
	{
		LOG_ERROR("[SimpleDll]action,key[%s-%s] execute fail! cannot find entry func!", strRelativePath.c_str(), strEntryFunc.c_str());
		return ASErr_FAIL;
	}
	
	pFunc();
	if(hModule)
		FreeLibrary(hModule);
	LOG_TRACE("[SimpleDll]action,key[%s-%s] execute success!", strRelativePath.c_str(), strEntryFunc.c_str());
	return ASErr_OK;
}