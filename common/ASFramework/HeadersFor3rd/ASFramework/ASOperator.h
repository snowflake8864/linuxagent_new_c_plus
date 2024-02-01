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
class IASPolicyHandler;

class IASOperaterBase : public IASBundle
{
public:
};

class IASExtOperater : public IASOperaterBase
{
public:
	//////////////////////////////////////////////////////////////////////////
	//创建util,用完请自行调用Release接口
	virtual IASLog* GetLoger() = 0;
	virtual IASBundle* CreateBundle() = 0;
	virtual std::string GetFrameworkDir() = 0;
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

namespace ASFrameworkOper
{
	//////////////////////////////////////////////////////////////////////////
	//asoperator的属性定义,统一为utf8字符串
	const char* const AS_OPER_KEY_FRAMEWORKDIR	= "as.oper.attr.frameworkdir";			//framework的安装目录
	const char* const AS_OPER_ATTR_DEFAULT_LOGDIR = "as.oper.attr.default_logdir";		//framework的默认日志目录
	const char* const AS_OPER_ATTR_DEFAULT_LOGLEVEL = "as.oper.attr.default_loglevel";	//framework的默认log级别

	//////////////////////////////////////////////////////////////////////////
	//asoperator支持创建的util
	const char* const AS_OPER_UTIL_BUNDLE = "as.oper.util.bundle";	//创建bundle,返回IASBundle指针
};

#endif /* ASOperater_h */
