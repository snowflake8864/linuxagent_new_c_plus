//
//  ASContentProvider.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASContentProvider_h
#define ASContentProvider_h

#include "ASFoundation.h"

class IASContentProvider : public IASBundle
{
public:
	
	virtual ASCode putIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey,int nValue) = 0;
	virtual ASCode putAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey,const char* lpValue) = 0;
	virtual ASCode putWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey,const wchar_t* lpValue) = 0;

	virtual ASCode getIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey,int* pResult) = 0;
	virtual ASCode getAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey,OUT char* lpBuffer,INOUT int* pBufLen) = 0;
	virtual ASCode getWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey,OUT wchar_t* lpBuffer,INOUT int* pBufLen) = 0;
};

class IASContentNotifyCallback
{
public:

	// 属性通知回调接口，由RegisterProvider发起通知，contentmgr派发，回调接口禁用耗时操作
	// 通知内容存放在pBundle中，bundle中存在的key有(详见下面描述)
	// AS_CONTENTATTR_CLASS、AS_CONTENTATTR_CLASS_KEY、AS_CONTENT_NOTIFY_DATATYPE、AS_CONTENT_NOTIFY_CONTENT
	virtual ASCode OnContentNotify(IASBundle* pBundle) = 0;
};

__servicename(IASContentProviderMgr, "as.svc.contentprovidermgr")
class IASContentProviderMgr : public IASFrameworkService
{
public:

	virtual ASCode RegisterProvider(IASOperaterBase* pOper,IASContentProvider* lpProvider) = 0;
	virtual ASCode UnRegisterProvider(IASOperaterBase* pOper,IASContentProvider* lpProvider) = 0;

	virtual ASCode putIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, int nValue) = 0;
	virtual ASCode putAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const char* lpValue) = 0;
	virtual ASCode putWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const wchar_t* lpValue) = 0;
	virtual ASCode getIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, int* pResult) = 0;
	virtual ASCode getAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, OUT char* lpBuffer, INOUT int* pBufLen) = 0;
	virtual ASCode getWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, OUT wchar_t* lpBuffer, INOUT int* pBufLen) = 0;

	virtual ASCode putInProcIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, int nValue) = 0;
	virtual ASCode putInProcAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const char* lpValue) = 0;
	virtual ASCode putInProcWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const wchar_t* lpValue) = 0;
	virtual ASCode getInProcIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, int* pResult) = 0;
	virtual ASCode getInProcAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, OUT char* lpBuffer, INOUT int* pBufLen) = 0;
	virtual ASCode getInProcWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, OUT wchar_t* lpBuffer, INOUT int* pBufLen) = 0;

	// 属性回调通知的注册与反注册接口(如果某个属性需要回调通知，则通过该接口进行注册)
	virtual ASCode RegisterNotifyCallback(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, IASContentNotifyCallback* pNotifyCallback) = 0;
	virtual ASCode UnRegisterNotifyCallback(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, IASContentNotifyCallback* pNotifyCallback) = 0;

	// 组件提供的属性要提供给其他组件回调通知，则需要使用这些接口通知到contentmgr进行派发
	virtual ASCode notifyIntContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, int nValue) = 0;
	virtual ASCode notifyAStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const char* lpValue) = 0;
	virtual ASCode notifyWStringContent(IASOperaterBase* pOper, const char* lpszClass, const char* lpKey, const wchar_t* lpValue) = 0;
};

namespace ASContentProvider
{
	const char* const ASCONTENTMGR_LOG_PREFIX = "as.log.contentmgr.";

	//content的类别,类似as.content.sd表示病毒查杀类
	const char* const AS_CONTENTATTR_CLASS = "as.content.attr.class";
	//content的类别中的key，参考ASContentClass.h
	const char* const AS_CONTENTATTR_CLASS_KEY = "as.content.attr.class.key";
	//content的名字,类似as.content.sd.sdsetting.cloudquerymode
	const char* const AS_CONTENTATTR_NAME = "as.content.attr.name";

	//通过ipc更新content时返回的结果,int,1表示成功,其他表示失败
	const char* const AS_CONTENT_UPDATERESULT_CODE = "as.content.updateresult.code";
	//通过ipc更新content时成功或失败的原因,utf8 string
	const char* const AS_CONTENT_UPDATERESULT_REASON = "as.content.updateresult.reason";

	//通过ipc查询content时返回的结果,int,1表示成功,其他表示失败
	const char* const AS_CONTENT_QUERYRESULT_CODE = "as.content.queryresult.code";
	//通过ipc查询content时成功或失败的原因,utf8 string
	const char* const AS_CONTENT_QUERYRESULT_REASON = "as.content.queryresult.reason";
	//通过ipc查询content时返回的内容,int
	const char* const AS_CONTENT_QUERYRESULT_CONTENT_INT = "as.content.queryresult.content_int";
	//通过ipc查询content时返回的内容,astring
	const char* const AS_CONTENT_QUERYRESULT_CONTENT_ASTRING = "as.content.queryresult.content_astring";
	//通过ipc查询content时返回的内容,wstring
	const char* const AS_CONTENT_QUERYRESULT_CONTENT_WSTRING = "as.content.queryresult.content_wstring";

	//content回调通知的数据内容
	const char* const AS_CONTENT_NOTIFY_CONTENT = "as.content.notify.content";
	//content回调通知的数据类型
	const char* const AS_CONTENT_NOTIFY_DATATYPE = "as.content.notify.datatype";
	const char* const AS_CONTENT_NOTIFY_DATATYPE_INT = "int";
	const char* const AS_CONTENT_NOTIFY_DATATYPE_ASTRING = "astring";
	const char* const AS_CONTENT_NOTIFY_DATATYPE_WSTRING = "wstring";

	//预置的一些content_provider的class
	const char* const AS_CONTENT_CLASS_FRAMEWORKINFO = "as.content.class.framework_info";

#ifdef _WINDOWS
	const char* const AS_CONTENTMGR_COMPONENT_NAME = "ASContentMgr.dll";
	const char* const AS_CONTENTMGR_COMPONENT_PATH = "entclient\\ASContentMgr.dll";
	const char* const AS_CONTENTMGR_COMPONENT_NAMEx64 = "ASContentMgr64.dll";
	const char* const AS_CONTENTMGR_COMPONENT_PATHx64 = "entclient\\ASContentMgr64.dll";
#endif
};

typedef IASContentProviderMgr* (__stdcall FNCreateASContentMgr)(IN IASFramework* lpFramework);
#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) IASContentProviderMgr* __stdcall CreateASContentMgr(IN IASFramework* lpFramework);
#endif

#endif /* ASContentProvider_h */

