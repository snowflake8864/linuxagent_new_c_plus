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
};


#endif