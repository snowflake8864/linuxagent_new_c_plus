//
//  ASFramework.h
//  ASFramework
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASFramework_h
#define ASFramework_h

#include "ASUnknown.h"

class IASFrameworkService : public IASBundle
{
public:

	virtual const char* getClass() = 0;
	virtual const char* getName() = 0;
};

class IASFramework : public IASBundle
{
public:
    
    virtual ASCode QueryFrameworkService(const char* lpName, OUT IASFrameworkService** ppService) = 0;    
};

namespace ASFramework
{
	//////////////////////////////////////////////////////////////////////////
	//framework自身的属性，除了AS_FRAMEWORK_ATTR_LOGLEVEL外统一为utf8字符串，通过bundle的getAString接口获取
	//framework的安装路径，如windows版为osec根目录，从这里获取的路径默认已经带了路径分隔符    
	const char* const AS_FRAMEWORK_ATTR_BASEDIR_UTF8	= "as.framework.attr.basedir";
	//framework的日志路径，utf-8字符串，已经自带路径分隔符      
	const char* const AS_FRAMEWORK_ATTR_LOGDIR_UTF8 = "as.framework.attr.logdir";

	//旧的工作路径，由于中文路径编码问题，已弃用
	const char* const AS_FRAMEWORK_ATTR_BASEDIR	= "as.framework.attr.basedir";
	//旧的工作路径，由于中文路径编码问题，已弃用    
	const char* const AS_FRAMEWORK_ATTR_LOGDIR = "as.framework.attr.logdir";

	//framework的日志等级，int
	const char* const AS_FRAMEWORK_ATTR_LOGLEVEL = "as.framework.attr.loglevel";
	//framework的日志文件最大size,单位为字节    
	const char* const AS_FRAMEWORK_ATTR_LOGMAXSIZE = "as.framework.attr.logsize";
	//framework的最大进程数，int
	const char* const AS_FRAMEWORK_ATTR_MAXPROCESSCNT = "as.framework.attr.maxprocesscnt";
	//framework是否已经初始化完成,char      
	const char* const AS_FRAMEWORK_ATTR_FRAMEWORKREADY = "as.framework.attr.framework_ready";
	//framework的进程类型,char      
	const char* const AS_FRAMEWORK_ATTR_PROCESSTYPE = "as.framework.attr.process_type";

	//////////////////////////////////////////////////////////////////////////
	//framework的各种服务组件声明，通过QueryFrameworkService可查到framework的各种组件
	//通讯代理模块,返回IASNetAgent指针
	const char* const AS_SVC_NETAGENT = "as.svc.netagent";
	//策略接收器,返回IASPolicyCom指针    
	const char* const AS_SVC_POLICYCOM 		= "as.svc.policy";
	//日志上报器    
	const char* const AS_SVC_REPORTER 		= "as.svc.reporter";
	//权限管理器,返回IASAuthorityControl指针
	const char* const AS_SVC_AUTHORITY_CONTROLLER = "as.svc.authority_controller";
	//模块化组件,返回IASModuleMgr指针
	const char* const AS_SVC_MODULARIZER = "as.svc.modularizer";
	//framework进程内置的ipcendpoint,返回IASIpcEndpoint指针,每个framework进程都会默认创建一个  
	const char* const AS_SVC_IPCENDPOINT	= "as.svc.ipcendpoint";
	//内容提供者管理器,返回IASContentProviderMgr指针
	const char* const AS_SVC_CONTENT_PROVIDERMGR = "as.svc.contentprovidermgr";
	//上传下载流量控制器,返回IASNetFlowMgr指针
	const char* const AS_SVC_NETFLOWMGR = "as.svc.netflowmgr";

	//////////////////////////////////////////////////////////////////////////
	//1.0版本的老组件，通过这些兼容的声明还可以查到  
	//1.0版本的IEntClient接口，老版本兼容使用  
	const char* const AS_SVC_OLD_ENTCLIENT 	= "as.svc.old.entclient";	
	//1.0版本的IIpcSvc接口，老版本兼容使用    
	const char* const AS_SVC_OLD_IPCSVC 	= "as.svc.old.ipcsvc";	
	//1.0版本的IIpcClient接口，老版本兼容使用    
	const char* const AS_SVC_OLD_IPCCLIENT 	= "as.svc.old.ipcclient";
	//1.0版本的IMsgClient接口，老版本兼容使用    
	const char* const AS_SVC_OLD_IPCENDPOINT = "as.svc.old.ipcendpoint";
	//1.0版本的通讯代理接口，老版本兼容使用    
	const char* const AS_SVC_OLD_NETAGENT 	= "as.svc.old.netagent";
	//1.0版本的策略接口，老版本兼容使用 
	const char* const AS_SVC_OLD_POLICY = "as.svc.old.policy";
	//1.0版本的上报接口，老版本兼容使用 
	const char* const AS_SVC_OLD_REPORTCOM = "as.svc.old.reportcom";
	//1.0版本的计划任务弹窗管理器接口，老版本兼容使用 
	const char* const AS_SVC_OLD_TASKWND_MGR 	= "as.svc.old.taskwndmgr";
	//1.0版本的模块化组件,老版本兼容使用 
	const char* const AS_SVC_OLD_MODULARIZER = "as.svc.old.modularizer";

	//////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////////
	//数据采集器引擎
	const char* const AS_FRAMEWORK_DATACLLOECT_ENGINE = "as.svc.datacollect_engine";
	//////////////////////////////////////////////////////////////////////////
#ifdef _WINDOWS
	const char* const ASIpcEndpoint_Name = "ASIpcEndpoint.dll";
	const char* const ASIpcEndpoint_Path = "EntClient\\ASIpcEndpoint.dll";
#endif
    
#ifdef __linux__
    const char* const ASIpcEndpoint_Name = "asipcendpoint.so";
    const char* const ASIpcEndpoint_Path = "/Frameworks/asipcendpoint.so";
#endif
    
#ifdef __APPLE__
    const char* const ASIpcEndpoint_Name = "libASIpcEndpoint.dylib";
    const char* const ASIpcEndpoint_Path = "/Frameworks/libASIpcEndpoint.dylib";
#endif
    
};

#ifndef __nameof
#define __nameof(x) (ASFramework::AS_SVC_##x)
#endif

#ifndef __servicename
#define __servicename(x,y) namespace ASFramework {const char* const AS_SVC_##x = y;};
#endif
typedef IASFrameworkService* (__stdcall FCreateFrameworkSvc)(IN IASFramework* pFramework,IN IASBundle* pParams);

#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) IASFrameworkService* __stdcall CreateFrameworkSvc(IASFramework* pFramework, IASBundle* pParams);
#endif

#endif /* ASFramework_h */



