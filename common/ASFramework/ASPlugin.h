//
//  ASPlugin.h
//
//
//  Created by dengfan on 16/4/14.
//  Copyright © 2016年 dengfan. All rights reserved.
//

#ifndef ASPlugin_h
#define ASPlugin_h

#include "ASFoundation.h"

class IASPlugin : public IASUnknown,public IASBundleBase
{
public:
	//插件初始化,返回false时不会被框架加载
	virtual bool PluginInit() = 0;
	//插件开始运行,一般在这里开启工作线程等
	virtual bool PluginStart() = 0;
	//插件是否可停止,插件升级或模块卸载时会调用这个接口,返回false表示不可停止
	virtual bool PluginQueryStop() = 0;
	//插件停止,插件升级或模块卸载时会调用这个接口,返回false表示不可停止
	virtual bool PluginStop() = 0;
	//插件资源释放,这里应该注销申请的资源,停止工作线程等,下一步就是FreeLibrary了    
	virtual void PluginRelease() = 0;

	//获取一些默认接口,在插件配置中注册则需要提供这些接口,自行用代码注册的不需要提供    
	virtual IASPolicyHandler* GetTaskHandler(int ntaskType) = 0;
	virtual IASIpcReceiver* GetIpcReceiver(const char* lpszName) = 0;
	virtual IASFuncProvider* GetFuncProvider(const char* lpszName) = 0;
	virtual IASPolicyHandler* GetPolicyHandler(const char* lpszType) = 0;
	virtual IASContentProvider* GetContentProvider(const char* lpszName) = 0;
	virtual void* GetPluginInterface(const char* lpszName) = 0;
};

namespace ASPlugin
{
	//ASPlugin的属性，都在模块xml中配置，内部保存时值全用utf-8 char字符串
	const char* const AS_PLUGIN_ATTR_NAME = "name";
	const char* const AS_PLUGIN_ATTR_PATH = "path";
	const char* const AS_PLUGIN_ATTR_RUNINSVC = "svc";		//是否必需在服务进程运行（windows only），window默认为0,其它平台默认为1
	const char* const AS_PLUGIN_ATTR_HOTPLUG = "hotplug";	//是否支持热插拔，默认为1
	//////////////////////////////////////////////////////////////////////////
	//插件声明的需要默认注册的服务或handler
	const char* const AS_PLUGIN_COMPONET_TASK = "task";					//插件需要处理任务
	const char* const AS_PLUGIN_COMPONET_POLICY = "policy";				//插件需要处理策略
	const char* const AS_PLUGIN_COMPONET_IPCRECEIVER = "ipc_receiver";	//插件需要接收ipc消息
	const char* const AS_PLUGIN_COMPONET_FUNCTION = "func_provider";	//插件可提供某个功能
	const char* const AS_PLUGIN_COMPONET_CONTENT = "content_provider";	//插件提供了一个content_provider

	const char* const AS_PLUGIN_COMPONET_KEY_TASKTYPE = "type";
	const char* const AS_PLUGIN_COMPONET_KEY_CONFTYPE = "conftype";
	const char* const AS_PLUGIN_COMPONET_KEY_FUNCNAME = "func";
	const char* const AS_PLUGIN_COMPONET_KEY_CONTENCLASS = "class";
	const char* const AS_PLUGIN_COMPONET_KEY_MSGTYPE = "msg_type";

	//////////////////////////////////////////////////////////////////////////
	//插件要处理的策略或任务,1.0兼容逻辑
	const char* const AS_PLUGIN_COMPONET_TASK_OLD = "Policy";			//插件需要处理任务
	const char* const AS_PLUGIN_COMPONET_CONFTYPE_OLD = "ConfType";		//插件需要处理策略

	// 内部用的IASPlugin和Operator指针，二进制
	const char* const AS_PLUGIN_ATTR_IASPOINTER = "IASPlugin_Pointer";
	const char* const AS_PLUGIN_OPERATOR_POINTER = "IASOperator_Pointer";
};

typedef IASPlugin* (__stdcall FCreateASPlugin)(IN IASOperater* lpOperator);
extern "C" IASPlugin* __stdcall CreateASPlugin(IN IASOperater* lpOperator);


#endif /* ASPlugin_h */
