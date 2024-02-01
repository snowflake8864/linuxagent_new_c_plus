#include "stdafx.h"
#include "ASIpcAction.h"
#include "utils/string_utils.hpp"
using namespace ASIpcAction;

#ifdef _WINDOWS
#include <entclient_old/ipc/IDS.h>
#include <entclient_old/ipc/IMsgClient.h>
#endif

#ifndef LOG_ERROR
#define LOG_ERROR
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG
#endif

ASCode CASIpcAction::Execute()
{
	//todo 
	return ASErr_OK;
}

ASCode CASMsgAction::Execute()
{
#ifdef _WINDOWS
	std::string strDst		 = getBundleAString(this, AS_IPCACTION_OLDKEY_DST,"");
	std::string strContent	 = getBundleAString(this, AS_IPCACTION_OLDKEY_CONTENT,"");
	std::string strDataType	 = getBundleAString(this, AS_IPCACTION_OLDKEY_DATATYPE,"");
	std::string strBoardcast = getBundleAString(this, AS_IPCACTION_OLDKEY_BROADCAST,"0");

	if (strContent.length() <= 0 || strDataType.length() <= 0 || (strBoardcast == "0" && strDst.length() <= 0))
	{
		LOG_ERROR("[msg] action,key[%s-%s-%s] execute fail! invalid parameter", strDst.c_str(), strDataType.c_str(), strContent.c_str());
		return ASErr_FAIL;
	}

	int nLen = 0;
	unsigned char* lpIpcPointer = getBundleBinary(this, AS_IPCACTION_ATTR_OLDENDPOINT_POINTER, nLen);
	if (!lpIpcPointer || nLen != sizeof(IMsgClient*) || !(*((IMsgClient**)lpIpcPointer)))
	{
		if (lpIpcPointer)	delete[] lpIpcPointer;
		LOG_ERROR("[msg] action,key[%s-%s-%s] execute fail!no endpoint pointer. [%d-%d-%08x]",strDst.c_str(),strDataType.c_str(), strContent.c_str(),nLen,sizeof(IMsgClient*), (int)lpIpcPointer);
		return ASErr_FAIL;
	}

	IMsgClient* pMsgClient = *((IMsgClient**)lpIpcPointer);
	if(strBoardcast != "0")
	{
		if (pMsgClient->SendBroadcastData(atoi(strDataType.c_str()), (LPVOID)strContent.c_str(), sizeof(char) * (strContent.length() + 1)))
		{
			LOG_TRACE("[msg] action,key[%s-%s-%s] execute successfully!", strDst.c_str(), strDataType.c_str(), strContent.c_str());
			return ASErr_OK;
		}
		else
		{
			LOG_ERROR("[msg] action,key[%s-%s-%s] execute fail! ipc_err[%d]", strDst.c_str(), strDataType.c_str(), strContent.c_str(), pMsgClient->GetLastErrorCode());
			return ASErr_FAIL;
		}
	}
	else
	{
		// msg��dst�ֶ�Ϊ gid1:cid1|gid2:cid2 �����ĸ�ʽ
		std::vector<std::string> lstDst;
		string_utils::Split(lstDst, strDst, "|");
		if(lstDst.size() <= 0)
		{
			LOG_ERROR("[msg] action,key[%s-%s-%s] execute fail![dst is invalid!]", strDst.c_str(), strDataType.c_str(), strContent.c_str());
			return ASErr_FAIL;
		}

		for(std::vector<std::string>::iterator it = lstDst.begin(); it != lstDst.end(); ++it)
		{
			size_t nPos = it->find(":");
			if(std::string::npos == nPos)	continue;

			int nGid = atoi(it->substr(0,nPos).c_str());
			int nCid = atoi(it->substr(nPos + 1, std::string::npos).c_str());

			wstring strContentw = CA2W(strContent.c_str());

			if (pMsgClient->SendData((UINT)atoi(strDataType.c_str()), (LPVOID)strContentw.c_str(), sizeof(wchar_t) * (strContentw.length() + 1), MAKECLIENTID(nGid, nCid)))
			{
				LOG_TRACE("[msg] action,key[%s-%s-%s] execute successfully!", strDst.c_str(), strDataType.c_str(), strContent.c_str());
			}
			else
			{
				LOG_ERROR("[msg] action,key[%s-%s-%s] execute fail! ipc_err[%d]", strDst.c_str(), strDataType.c_str(), strContent.c_str(), pMsgClient->GetLastErrorCode());
				return ASErr_FAIL;
			}
		}
		return ASErr_OK;
	}
#endif
	return ASErr_FAIL;
}