//
//  ASPolicyCom.h
//  policycom
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASPolicyCom_h
#define ASPolicyCom_h

#include "ASFoundation.h"

class IASPolicyHandler
{
public:
	virtual ASCode OnNewPolicy(IASBundle* pData,IASBundle* pRetData) = 0;
};

__servicename(IASPolicyCom, "as.svc.policy")
class IASPolicyCom : public IASFrameworkService
{
public:

	virtual ASCode Init() = 0;

	//创建其他接口，目前未实现
	virtual ASCode CreateInstance(const char* clsid, void** ppInterface) = 0;

	//注册注销handler,pParams里应填充的参数参见ASPolicyCom里的定义
	virtual ASCode RegisterHandler(IASOperaterBase* pOper,IASBundle* pData) = 0;

	virtual ASCode UnRegisterHandler(IASOperaterBase* pOper,IASBundle* pData) = 0;

	//策略完成接口,策略执行完成时请调用这个接口通知框架,框架会处理接受下一条和上报完成等逻辑
	virtual ASCode FinishPolicy(IASOperaterBase* pOper,IASBundle* pPolData) = 0;

	//刷新策略接口,可以通过这里取得当前最新的策略,或手动去控制中心更新一次
	virtual ASCode RefreshPolicy(IASOperaterBase* pOper,IASBundle* pInData,IASBundle* pOutData) = 0;
};

namespace ASPolicyCom
{
	//////////////////////////////////////////////////////////////////////////
	//任务执行结果代码,0:成功|1:用户取消|2:超时|3:出错|4:服务端取消|5终端不支持
	const long ASTaskResult_Success = 0;
	const long ASTaskResult_UserCancel = 1;
	const long ASTaskResult_Timeout = 2;
	const long ASTaskResult_ExecuteFail = 3;
	const long ASTaskResult_ServerCancel = 4;
	const long ASTaskResult_NotSupported = 5;

	//////////////////////////////////////////////////////////////////////////
	//策略和任务的各种属性,注册和注销接口、OnNewPolicy的bundle参数里可以用这些属性取内容
	//任务的id,int类型,OnNewPolicy里可以取到
	const char* const AS_POLICYATTR_ID = "as.policy.attr.id";
	//任务的type,int类型,注册注销时用到,任务类型具体定义参见ASPolicyTypes.h
	const char* const AS_POLICYATTR_TYPE = "as.policy.attr.type";
	//策略的conftype,string类型,注册注销时用到,任务类型具体定义参见ASPolicyTypes.h
	const char* const AS_POLICYATTR_CONFTYPE = "as.policy.attr.conftype";
	//任务或策略的内容,统一为utf8编码的json字符串,OnNewPolicy里可以取到
	const char* const AS_POLICYATTR_CONTENT = "as.policy.attr.content";
	//调用FinishPolicy时报告给控制中心的完成信息,一般为utf8的json字符串
	const char* const AS_POLICYATTR_FINISHDETAIL = "as.policy.attr.finish_detail";
	//注册注销handler时传入,binary类型,请传入IASPolicyHandler*指针的地址
	const char* const AS_POLICYATTR_HANDLER_POINTER = "as.policy.attr.handler_pointer";
	//调用RefreshPolicy接口获取当前最新策略时用到的属性,依次为从缓存获取、从控制中心获取、从控制中心获取失败时用缓存,都是int  
	const char* const AS_POLICYATTR_REFRESH_BY_CACHE = "as.policy.attr.refresh_by_cache";
	const char* const AS_POLICYATTR_REFRESH_BY_CONSOLE = "as.policy.attr.refresh_by_console";
	const char* const AS_POLICYATTR_REFRESH_BY_CACHE_ON_FAIL = "as.policy.attr.refresh_by_cache_on_fail";
	//从RefreshPolicy获取到的当前策略,utf8编码的字符串
	const char* const AS_POLICYATTR_REFRESH_RESULT = "as.policy.attr.refresh_result";

	//////////////////////////////////////////////////////////////////////////
	//policycom的各种属性,统一为utf8编码的字符串
	//policycom的运行模式,server模式会从控制台接收策略并派发,client模式时不自己接收策略只从ipc监听
	const char* const AS_POLICYCOMATTR_NOIPC	= "as.policycom.attr.noipc";
	const char* const AS_POLICYCOMATTR_CONFTYPE	= "as.policycom.attr.conftype";
	const char* const AS_POLICYCOMATTR_TASKTYPE	= "as.policycom.attr.tasktype";
	const char* const AS_POLICYCOMATTR_SUPPORTTED_TASKTYPE	= "as.policycom.attr.supported_tasktype";
	const char* const AS_POLICYCOMATTR_CONFTOPLUGIN_TABLE	= "as.policycom.attr.conftype_to_plugin_table";
	const char* const AS_POLICYCOMATTR_LOGOUT_KEEP_USERPOLICY_CONFTYPE = "as.policycom.attr.logout_keep_userpolicy_conftype";
	//要接受的third conf，由外部提供
	const char* const AS_POLICYCOMATTR_THIRDPARTY_CONFTYPE	= "as.policycom.attr.thitdparty_conftype";

	const char* const AS_POLICYCOMATTR_RUNTYPE	= "as.policycom.attr.run_mode";
	const char* const AS_POLICYCOMATTR_SERVERMODE = "as.policycom.attr.server_mode";
	const char* const AS_POLICYCOMATTR_CLIENTMODE = "as.policycom.attr.client_mode";
	const char* const AS_POLICYCOMATTR_THIRDCLIENTMODE = "as.policycom.attr.third_client_mode";

	const char* const AS_POLICY_LOG_FILTER = "as.log.policycom";
};


#endif
