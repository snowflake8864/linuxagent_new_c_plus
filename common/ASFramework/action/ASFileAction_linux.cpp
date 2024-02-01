#include "stdafx.h"
#include "ASFileAction.h"
#include "CActionFunc.h"
#include "utils/file_utils.h"
#include <stdio.h>


ASCode CASFileActionTravel::Execute()
{
	string strSubType = ASBundleHelper::getBundleAString(this, ASFileAction::AS_FILEACTION_KEY_SUBTYPE, "");
	if(strSubType.length() <= 0)	return ASErr_FAIL;

	string strDir = ASBundleHelper::getBundleAString(this, ASFileAction::AS_RUNACTION_ATTR_BASEDIR, "");

	if(strSubType == ASFileAction::AS_FILEACTION_SUBTYPE_MOVEDTOMODULE)
	{
		string strRelativePath = ASBundleHelper::getBundleAString(this,ASFileAction::AS_FILEACTION_KEY_FILE,"");
		if(strRelativePath.length() <= 0)	return ASErr_FAIL;

		int nDestModState = ASModularize::AS_MODSTATE_UNKNOWN;
		string strFullPath = strDir + strRelativePath.c_str();
		string strDestModule = ASBundleHelper::getBundleAString(this,ASFileAction::AS_FILEACTION_KEY_DEST,"");
		string strState = ASBundleHelper::getBundleAString(this, ASFileAction::AS_FILEACTION_KEY_INSTALL_STATE,"1");
		if(strDestModule.length() <= 0 /*|| (CASModuleMgr::GetModuleState(strDestModule.c_str(),nDestModState) && nDestModState != AS_MODSTATE_INSTALLED && 
			nDestModState != AS_MODSTATE_UNINSTALL_PENDING)*/)
		{
			LOG_TRACE("file %s ,dest mod %s,state %d,will delete",strFullPath.c_str(),strDestModule.c_str(),nDestModState);
			return _DeleteFile(strFullPath.c_str()) ? ASErr_OK : ASErr_FAIL;
		}

		return ASErr_OK;
	}

	LOG_ERROR("unknown subtype %s",strSubType.c_str());
	return ASErr_INVALIDARG;
}

bool CASFileActionTravel::_DeleteFile(const char* lpszFile)
{
	assert(lpszFile && strlen(lpszFile));
	return file_utils::RemoveFile(lpszFile);
}


ASCode CASCopyFileAction::Execute()
{
	string strRelativePath = ASBundleHelper::getBundleAString(this,ASFileAction::AS_FILEACTION_KEY_Scr,"");
	if(strRelativePath.length() <= 0)	return ASErr_FAIL;

	string strScrPath = strRelativePath;

	string strIfUpd = ASBundleHelper::getBundleAString(this,AS_ACTION_IF_UPDATE,"");
	string strUpdFiles = ASBundleHelper::getBundleAString(this,AS_MSGACTION_KEY_CONTENT,"");
	bool bIfupd = strIfUpd == "1" ? true : false;
	string strFileName = strScrPath.substr(strScrPath.rfind('\\') + 1);
	if(bIfupd && !CActionFunc::BInList(strFileName.c_str(), strUpdFiles.c_str()))
	{
		LOG_ERROR("配置了升级后才执行的动作,且文件不在升级文件列表中，不执行动作，%s",strScrPath.c_str());
		return ASErr_OK;
	}

	string strDir = ASBundleHelper::getBundleAString(this, ASFileAction::AS_RUNACTION_ATTR_BASEDIR, "");

	CActionFunc::GetRealPath(strDir, strScrPath); 
	strRelativePath = ASBundleHelper::getBundleAString(this,ASFileAction::AS_FILEACTION_KEY_DEST,"");
	string strDestPath = strRelativePath;
	CActionFunc::GetRealPath(strDir, strDestPath); 

	if(strDestPath.length() <= 0 || !file_utils::IsExist(strScrPath))
	{
		LOG_ERROR("xml 配置错误, src file = %s ,dest = %s",strScrPath.c_str(),strDestPath.c_str());
		return ASErr_FAIL;
	}

	file_utils::MakeDirs(strDestPath);
	bool bRet = false;
	int nTry = 0;
	do 
	{
		nTry ++;
		if (CActionFunc::EntSafeCopyFile(strScrPath.c_str(), strDestPath.c_str()))
		{
			bRet = true;
			break;
		}
	} while (nTry < 3);
	if(!bRet)
	{
		return ASErr_FAIL;
	}

	return ASErr_OK;
}

ASCode CASMoveFileAction::Execute()
{
	std::string strRelativePath = ASBundleHelper::getBundleAString(this,ASFileAction::AS_FILEACTION_KEY_Scr,"");
	if(strRelativePath.length() <= 0)	return ASErr_FAIL;

	std::string strScrPath = strRelativePath;
	std::string strIfUpd = ASBundleHelper::getBundleAString(this,AS_ACTION_IF_UPDATE,"");
	std::string strUpdFiles = ASBundleHelper::getBundleAString(this,AS_MSGACTION_KEY_CONTENT,"");
	bool bIfupd = strIfUpd == "1" ? true : false;
	std::string strFileName = strScrPath.substr(strScrPath.rfind('\\') + 1);
	if(bIfupd && !CActionFunc::BInList(strFileName.c_str(), strUpdFiles.c_str()))
	{
		LOG_ERROR("配置了升级后才执行的动作,且文件不在升级文件列表中，不执行动作，%s",strScrPath.c_str());
		return ASErr_OK;
	}

	string strDir = ASBundleHelper::getBundleAString(this, ASFileAction::AS_RUNACTION_ATTR_BASEDIR, "");
	CActionFunc::GetRealPath(strDir,strScrPath); 
	strRelativePath = ASBundleHelper::getBundleAString(this,ASFileAction::AS_FILEACTION_KEY_DEST,"");
	std::string strDestPath = strRelativePath;
	CActionFunc::GetRealPath(strDir, strDestPath); 
	if(strDestPath.length() <= 0 || !file_utils::IsExist(strScrPath))
	{
		LOG_ERROR("xml 配置错误, src file = %s ,dest = %s",strScrPath.c_str(),strDestPath.c_str());
		return ASErr_FAIL;
	}
	file_utils::MakeDirs(strDestPath);
	if(!CActionFunc::SafeMoveFile(strScrPath.c_str(),strDestPath.c_str(),1))
	{
		return ASErr_FAIL;
	}

	return ASErr_OK;
}
