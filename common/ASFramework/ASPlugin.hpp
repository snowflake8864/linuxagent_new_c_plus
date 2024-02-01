//
//  ASPlugin.hpp
//
//
//  Created by dengfan on 16/4/14.
//  Copyright © 2016年 dengfan. All rights reserved.
//

#ifndef ASPlugin_hpp
#define ASPlugin_hpp

#include <string>
#include "ASFoundation.h"

class CASPlugin : public IASPlugin, public IASIpcReceiver, public IASPolicyHandler, public IASFuncProvider, public IASContentProvider
{
public:

	ASUNKNOWN_EASY_IMPLEMENT(CASPlugin)
	ASBUNDLE_EASY_IMPLEMENT_BY_POINTER(CASPlugin)

public:

public:

	virtual bool PluginInit() { return true; }
	virtual bool PluginStart() { return true; }
	virtual bool PluginQueryStop() { return true; }
	virtual bool PluginStop() { return true; }
	virtual void PluginRelease() {}

public:

	virtual IASIpcReceiver* GetIpcReceiver(const char* lpszName) { return this; }
	virtual IASFuncProvider* GetFuncProvider(const char* lpszName) { return this; }
	virtual IASPolicyHandler* GetTaskHandler(int nType) { return this; }
	virtual IASPolicyHandler* GetPolicyHandler(const char* lpszName) { return this; }
	virtual IASContentProvider* GetContentProvider(const char* lpszName) { return this; }
	virtual void* GetPluginInterface(const char* lpszName) { return NULL; }

public:

	//ipc receiver,想自己处理ipc消息请重写这个接口
	virtual ASCode OnIpcMessage(IASBundle* pIPCData, IASBundle* pResult) { return ASErr_NOIMPL; }

	// func provider,想提供功能供他人调用请求请重写这套接口
	virtual ASCode OnActionRequest(IASBundle* pRequest) { return ASErr_NOIMPL; }
	virtual ASCode OnActionRequestForResult(IASBundle* pRequest, IASBundle* pResult) { return ASErr_NOIMPL; }
	virtual ASCode OnActionRequestForResultAsync(IASBundle* pRequest, IASActionResultReceiver* pReceiver) { return ASErr_NOIMPL; }

	// policy handler,想自己处理任务或策略请重写这个接口
	virtual ASCode OnNewPolicy(IASBundle* pPolData, IASBundle* pResult) { return ASErr_NOIMPL; }

	//content provider,想提供某个class的content查询响应请重写这个接口
	virtual ASCode putIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, int nValue) { return ASErr_NOIMPL; }
	virtual ASCode putAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const char* lpValue) { return ASErr_NOIMPL; }
	virtual ASCode putWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const wchar_t* lpValue) { return ASErr_NOIMPL; }
	virtual ASCode getIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, int* pResult) { return ASErr_NOIMPL; }
	virtual ASCode getAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, OUT char* lpBuffer, INOUT int* pBufLen) { return ASErr_NOIMPL; }
	virtual ASCode getWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, OUT wchar_t* lpBuffer, INOUT int* pBufLen) { return ASErr_NOIMPL; }

public:

	ASCode ListenTask(int nType) { return m_pOperator ? m_pOperator->RegisterTaskHandler(nType, this) : ASErr_FAIL; }
	ASCode UnListenTask(int nType) { return m_pOperator ? m_pOperator->UnRegisterTaskHandler(nType, this) : ASErr_FAIL; }
	ASCode FinishTask(int nType, int nId, const char* lpszDetail) { return m_pOperator ? m_pOperator->FinishTask(nType, nId, lpszDetail) : ASErr_FAIL; }

	ASCode ListenPolicy(const char* lpszConfType) { return m_pOperator ? m_pOperator->RegisterPolicyHandler(lpszConfType, this) : ASErr_FAIL; }
	ASCode UnListenPolicy(const char* lpszConfType) { return m_pOperator ? m_pOperator->UnRegisterPolicyHandler(lpszConfType, this) : ASErr_FAIL; }

	ASCode ReportLog(const char* lpszType, const char* lpszApi, unsigned char* lpContent, unsigned int nContLen)
	{
		return m_pOperator ? m_pOperator->ReportLog(lpszType, lpszApi, lpContent, nContLen) : ASErr_FAIL;
	}

	ASCode SendIpc(const char* lpszMsgType, const char* lpszDest, const char* lpContent, unsigned int nContentLen)
	{
		return m_pOperator ? m_pOperator->SendIpc(lpszMsgType, lpszDest, lpContent, nContentLen) : ASErr_FAIL;
	}

	ASCode SendIpcForResult(const char* lpszMsgType, const char* lpszDest, const char* lpContent, unsigned int nContentLen, IASBundle* pResultData)
	{
		return m_pOperator ? m_pOperator->SendIpcForResult(lpszMsgType, lpszDest, lpContent, nContentLen, pResultData) : ASErr_FAIL;
	}

	ASCode SendIpcForResultAsync(const char* lpszMsgType, const char* lpszDest, const char* lpContent, unsigned int nContentLen, IASIpcResultReceiver* pReceiver)
	{
		return m_pOperator ? m_pOperator->SendIpcForResultAsync(lpszMsgType, lpszDest, lpContent, nContentLen, pReceiver) : ASErr_FAIL;
	}

	int GetIntContent(const char* lpszClass, const char* lpszKey, int nDefault, bool bInproc)
	{
		assert(m_pOperator);
		if (!m_pOperator)	return nDefault;
		int nResult = -1;
		return (ASErr_OK == m_pOperator->getIntContent(lpszClass, lpszKey, &nResult, bInproc)) ? nResult : nDefault;
	}

	std::string GetAStringContent(const char* lpszClass, const char* lpszKey, const char* lpszDefault, bool bInProc)
	{
		assert(m_pOperator);
		char* lpszBuf = NULL;
		std::string strDefault = lpszDefault ? lpszDefault : "";
		do
		{
			if (!m_pOperator)
				break;

			int nBufLen = 0;
			if (ASErr_INSUFFICIENT_BUFFER != m_pOperator->getAStringContent(lpszClass, lpszKey, NULL, &nBufLen, bInProc) || nBufLen < 0)
				break;

			lpszBuf = new char[nBufLen + 1];
			memset(lpszBuf, 0, sizeof(char) * (nBufLen + 1));
			if (ASErr_OK != m_pOperator->getAStringContent(lpszClass, lpszKey, lpszBuf, &nBufLen, bInProc))
				break;

			strDefault = lpszBuf;

		} while (false);

		if (lpszBuf) delete[] lpszBuf;
		return strDefault;
	}

	std::wstring GetWStringContent(const char* lpszClass, const char* lpszKey, const wchar_t* lpszDefault, bool bInProc)
	{
		assert(m_pOperator);
		wchar_t* lpszBuf = NULL;
		std::wstring strDefault = lpszDefault ? lpszDefault : L"";
		do
		{
			if (!m_pOperator)
				break;

			int nBufLen = 0;
			if (ASErr_INSUFFICIENT_BUFFER != m_pOperator->getWStringContent(lpszClass, lpszKey, NULL, &nBufLen, bInProc) || nBufLen < 0)
				break;

			lpszBuf = new wchar_t[nBufLen + 1];
			memset(lpszBuf, 0, sizeof(wchar_t) * (nBufLen + 1));
			if (ASErr_OK != m_pOperator->getWStringContent(lpszClass, lpszKey, lpszBuf, &nBufLen, bInProc))
				break;

			strDefault = lpszBuf;

		} while (false);

		if (lpszBuf) delete[] lpszBuf;
		return strDefault;
	}

public:

	//默认构造函数，有些插件在非小助手运行没有asoper
	CASPlugin():m_pOperator(NULL),m_lRefCount_CASPlugin(0),m_pAttrBundle_CASPlugin(NULL){}
	//小助手插件一定要传asoper
	CASPlugin(IASOperater* p) : m_pOperator(p),m_lRefCount_CASPlugin(0) {assert(m_pOperator);  m_pOperator->AddRef(); m_pAttrBundle_CASPlugin = m_pOperator ? m_pOperator->CreateBundle() : NULL;}
	
	virtual ~CASPlugin() 
	{ 
		if (m_pAttrBundle_CASPlugin) m_pAttrBundle_CASPlugin->Release(); 
		if(m_pOperator) m_pOperator->Release();
	}

//插件如果要自己定义这几个日志宏的话，就用LOG_ASPLUGIN_USING_SELF禁掉此处的定义
#ifndef LOG_ASPLUGIN_USING_SELF
# define LOG_ERRORW(x,...)		{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteW(ASLog_Level_Error,x,__VA_ARGS__);pLog->Release();}}
# define LOG_TRACEW(x,...)		{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteW(ASLog_Level_Trace,x,__VA_ARGS__);pLog->Release();}}
# define LOG_DEBUGW(x,...)		{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteW(ASLog_Level_Debug,x,__VA_ARGS__);pLog->Release();}}
# define LOG_DIAGNOSEW(x,...)	{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteW(ASLog_Level_Diagnose,x,__VA_ARGS__);pLog->Release();}}
# define LOG_ERRORA(x,...)		{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteA(ASLog_Level_Error,x,__VA_ARGS__);pLog->Release();}}
# define LOG_TRACEA(x,...)		{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteA(ASLog_Level_Trace,x,__VA_ARGS__);pLog->Release();}}
# define LOG_DEBUGA(x,...)		{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteA(ASLog_Level_Debug,x,__VA_ARGS__);pLog->Release();}}
# define LOG_DIAGNOSEA(x,...)	{IASLog* pLog = NULL;if(m_pOperator && NULL != (pLog = m_pOperator->QueryLoger())) {pLog->WriteA(ASLog_Level_Diagnose,x,__VA_ARGS__);pLog->Release();}}
#endif

protected:

	IASOperater* m_pOperator;
};

typedef IASPlugin* (__stdcall FCreateASPlugin)(IN IASOperater* lpOperator);
extern "C" IASPlugin* __stdcall CreateASPlugin(IN IASOperater* lpOperator);


#endif /* ASPlugin_h */


