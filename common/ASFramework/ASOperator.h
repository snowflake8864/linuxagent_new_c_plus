//
//  ASOperator.h
//
//
//  Created by dengfan on 16/4/14.
//  Copyright © 2016年 dengfan. All rights reserved.
//

#ifndef ASOperater_h
#define ASOperater_h

#include "ASFoundation.h"

class IASLog;
class IASIpcEndpoint;
class IASPolicyHandler;
class IASContentProvider;
class IASIpcReceiver;
class IASIpcResultReceiver;
class IASBroadcastReceiver;
class IASActionResultReceiver;
class IASFuncProvider;
class IASActionResultReceiver;

class IASOperaterBase : public IASBundle
{
public:
};

class IASExtOperater : public IASOperaterBase
{
public:
	//////////////////////////////////////////////////////////////////////////
	//创建util,用完请自行调用Release接口
	virtual IASLog* QueryLoger() = 0;
	virtual IASBundle* CreateBundle() = 0;
	virtual const char* GetFrameworkDir() = 0;
	virtual void* CreateFrameworkUtil(const char* lpszUtilName) = 0;
	//////////////////////////////////////////////////////////////////////////
	//任务和策略类接口,bundle版接口中应填充的参数参见ASPolicyCom.h
	virtual ASCode RegisterTaskHandler(IASBundle* pParams) = 0;
	virtual ASCode UnRegisterTaskHandler(IASBundle* pParams) = 0;
	virtual ASCode FinishTask(IASBundle* pParams) = 0;
	virtual ASCode RefreshPolicy(IASBundle* pInData, IASBundle* pOutData) = 0;
	virtual ASCode RegisterPolicyHandler(IASBundle* pParams) = 0;
	virtual ASCode UnRegisterPolicyHandler(IASBundle* pParams) = 0;
	virtual ASCode RegisterTaskHandler(int nTaskType, IASPolicyHandler* pHandler) = 0;
	virtual ASCode UnRegisterTaskHandler(int nTaskType, IASPolicyHandler* pHandler) = 0;
	virtual ASCode FinishTask(int nTaskType, int nTaskId, const char* lpszFinishDetail) = 0;
	virtual ASCode RegisterPolicyHandler(const char* lpszConfType, IASPolicyHandler* pHandler) = 0;
	virtual ASCode UnRegisterPolicyHandler(const char* lpszConfType, IASPolicyHandler* pHandler) = 0;
	//////////////////////////////////////////////////////////////////////////
	//日志上报类接口,bundle中应填充的参数参见ASReportCom.h
	virtual ASCode ReportLog(IASBundle* pParams) = 0;
	virtual ASCode ReportLog(const char* lpszReportType, const char* lpszApi, unsigned char* lpContent, unsigned int nCotentLen) = 0;
};

class IASOperater : public IASOperaterBase
{
public:
	//////////////////////////////////////////////////////////////////////////
	//查询创建指针用完请自行调用Release接口
	virtual IASLog* QueryLoger() = 0;
	virtual IASBundle* CreateBundle() = 0;
	virtual const char* GetFrameworkDir() = 0;
	virtual void* CreateFrameworkUtil(const char* lpszUtilName) = 0;
	//////////////////////////////////////////////////////////////////////////
	//任务和策略类接口,bundle版接口中应填充的参数参见ASPolicyCom.h
	virtual ASCode RegisterTaskHandler(IASBundle* pParams) = 0;
	virtual ASCode UnRegisterTaskHandler(IASBundle* pParams) = 0;
	virtual ASCode FinishTask(IASBundle* pParams) = 0;
	virtual ASCode RefreshPolicy(IASBundle* pInData, IASBundle* pOutData) = 0;
	virtual ASCode RegisterPolicyHandler(IASBundle* pParams) = 0;
	virtual ASCode UnRegisterPolicyHandler(IASBundle* pParams) = 0;
	virtual ASCode RegisterTaskHandler(int nTaskType, IASPolicyHandler* pHandler) = 0;
	virtual ASCode UnRegisterTaskHandler(int nTaskType, IASPolicyHandler* pHandler) = 0;
	virtual ASCode FinishTask(int nTaskType,int nTaskId,const char* lpszFinishDetail) = 0;
	virtual ASCode RegisterPolicyHandler(const char* lpszConfType, IASPolicyHandler* pHandler) = 0;
	virtual ASCode UnRegisterPolicyHandler(const char* lpszConfType, IASPolicyHandler* pHandler) = 0;
	//////////////////////////////////////////////////////////////////////////
	//日志上报类接口,bundle中应填充的参数参见ASReportCom.h
	virtual ASCode ReportLog(IASBundle* pParams) = 0;
	virtual ASCode ReportLog(const char* lpszReportType,const char* lpszApi,unsigned char* lpContent,unsigned int nCotentLen) = 0;
	//////////////////////////////////////////////////////////////////////////
	//ipc接收器注册注销接口,bundle里必须保存的参数参见ASIpcEndpoint.h
	virtual ASCode RegisterIpcReceiver(IASBundle* pData) = 0;
	virtual ASCode UnRegisterIpcReceiver(IASBundle* pData) = 0;
	virtual ASCode RegisterBroadcastReceiver(IASBundle* pData) = 0;
	virtual ASCode UnRegisterBroadcastReceiver(IASBundle* pData) = 0;
	virtual ASCode RegisterIpcReceiver(const char* lpszMsgType, IASIpcReceiver* preceiver) = 0;
	virtual ASCode UnRegisterIpcReceiver(const char* lpszMsgType, IASIpcReceiver* preceiver) = 0;
	virtual ASCode RegisterBroadcastReceiver(const char* lpszMsgType, IASBroadcastReceiver* preceiver) = 0;
	virtual ASCode UnRegisterBroadcastReceiver(const char* lpszMsgType, IASBroadcastReceiver* preceiver) = 0;
	//////////////////////////////////////////////////////////////////////////
	//ipc发送接口,bundle里必须保存的参数参见ASIpcEndpoint.h
	virtual ASCode SendIpc(IASBundle* pIpcData) = 0;
	virtual ASCode SendBroadcast(IASBundle* pIpcData) = 0;
	virtual ASCode SendIpcForResult(IASBundle* pIpcData, IASBundle* pResultData) = 0;
	virtual ASCode SendIpcForResultAsync(IASBundle* pIpcData, IASIpcResultReceiver* pResultData) = 0;
	virtual ASCode SendIpc(const char* lpszMsgType,const char* lpszDest,const char* lpContent, unsigned int nContentLen) = 0;
	virtual ASCode SendBroadcast(const char* lpszMsgType, const char* lpContent, unsigned int nContentLen) = 0;
	virtual ASCode SendIpcForResult(const char* lpszMsgType, const char* lpszDest, const char* lpContent, unsigned int nContentLen, IASBundle* pResultData) = 0;
	virtual ASCode SendIpcForResultAsync(const char* lpszMsgType, const char* lpszDest, const char* lpContent, unsigned int nContentLen, IASIpcResultReceiver* pReceiver) = 0;
	//////////////////////////////////////////////////////////////////////////
	//content_provider的操作接口,参数细节参见ASContentProvider.h,bInproc表示是否调用进程内版本的接口
	virtual ASCode RegisterContentProvider(IASContentProvider* lpProvider) = 0;
	virtual ASCode UnRegisterContentProvider(IASContentProvider* lpProvider) = 0;
	virtual ASCode putIntContent(const char* lpszClass, const char* lpKey,int nValue,bool bInproc) = 0;
	virtual ASCode putAStringContent(const char* lpszClass, const char* lpKey, const char* lpValue, bool bInproc) = 0;
	virtual ASCode putWStringContent(const char* lpszClass, const char* lpKey, const wchar_t* lpValue, bool bInproc) = 0;
	virtual ASCode getIntContent(const char* lpszClass, const char* lpKey, int* pResult, bool bInproc) = 0;
	virtual ASCode getAStringContent(const char* lpszClass, const char* lpKey, OUT char* lpBuffer, INOUT int* pBufLen, bool bInproc) = 0;
	virtual ASCode getWStringContent(const char* lpszClass, const char* lpKey, OUT wchar_t* lpBuffer, INOUT int* pBufLen, bool bInproc) = 0;
	//////////////////////////////////////////////////////////////////////////
	//func_provider的操作接口,参数细节参见ASFuncProvider.h,目前暂未实现
	virtual ASCode RegisterFuncProvider(const char* lpszFunc, IASFuncProvider* lpProvider) = 0;
	virtual ASCode UnRegisterFuncProvider(const char* lpszFunc, IASFuncProvider* lpProvider) = 0;
	virtual ASCode RequestAction(const char* lpszFunc) = 0;
	virtual ASCode RequestActionForResult(const char* lpszFunc, IASBundle* pResult) = 0;
	virtual ASCode RequestActionForResultAsync(const char* lpszFunc, IASActionResultReceiver* pResultRecver) = 0;
	//////////////////////////////////////////////////////////////////////////
	//新增的一些接口
	virtual ASCode CreateIpcEndpoint(const char* lpszEpName,IASIpcEndpoint** lppPointer) = 0;
	 //调用前请获取AS_OPER_KEY_VERSION属性，版本大于等于2.0.0.1002才提供此接口
	virtual ASCode QueryFrameworkService(const char* lpName, OUT IASFrameworkService** ppService) = 0;
};

class IASOperater2 : public IASOperater
{
public:

	//申请流量配额，lpParams中应传入流向（上传、下载）、进程id、业务标识（combo）、是否自动分配、配额值（自动分配的情况下这个值无效） 
	virtual ASCode ApplyQuota(IASBundle* lpParams) = 0; 
	virtual ASCode ReturnQuota(IASBundle* lpParams) = 0;

	virtual ASCode ApplyQuota(const char* lpType, int nFlowDirection, int nApplyFlow, OUT int* nDivideFlows) = 0; 
	virtual ASCode ReturnQuota(const char* lpType, int nFlowDirection) = 0;
};

namespace ASFrameworkOper
{
	//////////////////////////////////////////////////////////////////////////
	//asoperator的属性定义,统一为utf8字符串
	const char* const AS_OPER_KEY_NAME 			= "as.oper.attr.name";					//operator的名字
	const char* const AS_OPER_KEY_VERSION 		= "as.oper.attr.version";				//operator的版本
	const char* const AS_OPER_KEY_OWNERNAME 	= "as.oper.attr.ownername";				//operator属主的名称,默认取文件名
	const char* const AS_OPER_KEY_OWNERPATH 	= "as.oper.attr.ownerpath";				//operator属主的全路径,默认取文件名,区分大小写
	const char* const AS_OPER_KEY_FRAMEWORKDIR	= "as.oper.attr.frameworkdir";			//framework的安装目录
	const char* const AS_OPER_ATTR_DEFAULT_LOGDIR = "as.oper.attr.default_logdir";		//framework的默认日志目录
	const char* const AS_OPER_ATTR_DEFAULT_LOGLEVEL = "as.oper.attr.default_loglevel";	//framework的默认log级别
	const char* const AS_OPER_ATTR_INDEPENDENT_LOGDIR = "as.oper.attr.independent_logdir";	//日志是否创建在独立的目录中，插件都要设置为1

#ifdef _WINDOWS
#ifdef _WIN64
	const char* const AS_OPER_COMPONENT_NAME = "ASOperator64.dll";
	const char* const AS_OPER_COMPONENT_PATH = "EntClient\\ASOperator64.dll";
#else
	const char* const AS_OPER_COMPONENT_NAME = "ASOperator.dll";
	const char* const AS_OPER_COMPONENT_PATH = "EntClient\\ASOperator.dll";
#endif
#endif
    

#ifdef __linux__
        const char* const AS_OPER_COMPONENT_NAME = "asoper.so";
        const char* const AS_OPER_COMPONENT_PATH = "/Frameworks/asoper.so";
#endif	

#ifdef __APPLE__
    const char* const AS_OPER_COMPONENT_NAME = "libASOper.dylib";
    const char* const AS_OPER_COMPONENT_PATH = "/Frameworks/libASOper.dylib";
#endif
	//////////////////////////////////////////////////////////////////////////
	//asoperator支持创建的util
	const char* const AS_OPER_UTIL_BUNDLE = "as.oper.util.bundle";	//创建bundle,返回IASBundle指针

	const char* const AS_OPER_CREATE_OPERATOR_INTERFACE_VERSION = "as.oper.create.operator.interface_version";	//CreateASOperatorExt,返回IASOperater指针
	const char* const AS_OPER_CREATE_OPERATOR_ONE = "as.oper.create.operator_one";	//CreateASOperatorExt,返回IASOperater指针
	const char* const AS_OPER_CREATE_OPERATOR_TWO = "as.oper.create.operator_two";	//CreateASOperatorExt, 返回IASOperater2指针
};

typedef IASOperater* (__stdcall FCreateASOperator)(IASFramework*,IASBundle* pData);
extern "C" IASOperater* __stdcall CreateASOperator(IASFramework* pFramework, IASBundle* pData);

typedef IASExtOperater* (__stdcall FCreateASExtOperator)(IASFramework*, IASBundle* pData);
extern "C" IASExtOperater* __stdcall CreateASExtOperator(IASFramework* pFramework, IASBundle* pData);

#endif /* ASOperater_h */
