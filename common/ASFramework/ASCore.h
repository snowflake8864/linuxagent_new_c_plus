//
//  ASCore.h
//  asframework
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASCore_h
#define ASCore_h

#include "ASFoundation.h"

class IASOperater;
class IASOperaterBase;
class IASExtOperater;

class IASAuthorityControl : public IASFrameworkService
{
public:

	virtual ASCode Init() = 0;
	virtual ASCode ReloadConf() = 0;
	virtual ASCode CheckAuthority(const char* lpszRight,IASBundle* pParams, IASOperaterBase* pOperator) = 0;
};

namespace ASCore
{
	//////////////////////////////////////////////////////////////////////////
	//ascore自身的各种属性,都是utf8字符串
	const char* const ASCORE_LOG_PREFIX = "as.log.core.";
	//ascore的运行模式
	const char* const ASCORE_ATTR_PROCESSTYPE = "as.core.attr.process_type";
	const char* const ASCORE_PROCESSTYPE_STDSRV = "as.core.processtype.std_srv";
	const char* const ASCORE_PROCESSTYPE_STDCLIENT = "as.core.processtype.std_client";
	const char* const ASCORE_PROCESSTYPE_OUTERCLIENT = "as.core.processtype.outer_client";
	const char* const ASCORE_PROCESSTYPE_3RDOUTERCLIENT = "as.core.processtype.3rd_outer_client";
};

namespace ASAuthorityControl
{
	//可以申请的权限的定义
	const char* const ASAUTHORITY_RIGHT_RECVTASK = "as.authority.right.recv_task";
	const char* const ASAUTHORITY_RIGHT_RECVCONF = "as.authority.right.recv_conf";
	const char* const ASAUTHORITY_RIGHT_LOGREPORT = "as.authority.right.log_report";
	const char* const ASAUTHORITY_RIGHT_SENDIPC = "as.authority.right.log_report";

	const char* const ASAUTHORITY_ATTR_OWNER = "as.authority.attr.owner";

};

typedef IASFramework* (__stdcall FCreateASFramework)(IN const char* p);
#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) IASFramework* __stdcall CreateASFramework(IN const char* pszType);
#endif

typedef  bool __stdcall FInitASFramework(IASBundle* pParam,OUT IASOperater** lppOperator);
#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) bool __stdcall InitASFramework(IASBundle* pParam, OUT IASOperater** lppOperator);
#endif

typedef  bool __stdcall FInitASFrameworkEx(IASBundle* pParam,OUT IASOperater** lppOperator);

typedef  bool __stdcall FExtInitASFramework(OUT IASExtOperater** lppOperator);
#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) bool __stdcall ExtInitASFramework(OUT IASExtOperater** lppOperator);
#endif

#endif //ASCore_h
