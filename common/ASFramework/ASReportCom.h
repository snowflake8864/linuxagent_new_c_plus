//
//  ASPolicyCom.h
//  policycom
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASReportCom_h
#define ASReportCom_h

#include "ASFoundation.h"

class IASOperaterBase;

class IASReportFilter
{
public:
	//pInData: 常规的天6上报日志，可能会对其内容做任何修改; 
	//pOutData: 过滤后日志，上报后调用者delete，该指针可能为NULL，如果为NULL，过滤者负责上报
	virtual ASCode FilterData(IN IASBundle* pInData, OUT IASBundle** ppOutData) = 0;
};

__servicename(IASReportCom, "as.svc.reporter")
class IASReportCom : public IASFrameworkService
{
public:
	virtual ASCode Init() = 0;
	virtual ASCode ReloadConf() = 0;
	virtual ASCode CreateInstance(const char* lpszKey, void** ppInterface) = 0;
	virtual ASCode Report(IASOperaterBase* pOper, IASBundle* pData) = 0;
	virtual ASCode RegisterFilter(IASOperaterBase* pOper,IN const char* lpFilterTypes, IN IASReportFilter* pFilter) = 0;
	virtual ASCode UnRegisterFilter(IASOperaterBase* pOper,IN const char* lpFilterTypes, IN IASReportFilter* pFilter) = 0;
};

namespace ASReportCom
{
	//////////////////////////////////////////////////////////////////////////
	const char* const UPLOAD_CLIENT_LOG_API		= "api/upload_client_log.json";
	const char* const CHECK_ALLOW_UPGRADE_API	= "api/check_upgrade.json";

	//////////////////////////////////////////////////////////////////////////
	//上报数据的属性,Report接口的IASBundle参数里保存
	//是否关键数据,1为关键0非关键,int
	const char* const AS_REPORT_ATTR_CRITICAL = "as.report.attr.critical";
	//是否同步上报,int,1为同步上报0为异步
	const char* const AS_REPORT_ATTR_SYNC = "as.report.attr.synchronous";
	//用户异步上报实时返回，上报数据由上报模块放在单独线程处理，不保证数据一定上报成功
	const char* const AS_REPORT_ATTR_USERASYNREALTIME = "as.report.attr.user_asyn_realtime";
	//上报到哪个api,如upload_client_log.json,utf8 string
	const char* const AS_REPORT_ATTR_API = "as.report.attr.api";
	//上报到哪,ip:port的格式非控制中心时需要指定这个参数,多用于要用天擎的上报格式上报但不是控制中心的情况如缓存服务器
	const char* const AS_REPORT_ATTR_ADDR = "as.report.attr.addr";
	//上报方法,get、post,int
	const char* const AS_REPORT_ATTR_METHOD = "as.report.attr.method";
	//上报到哪个url,这种模式时不会自动在后面拼接mid、ver等参数,一般用于非天擎控制中心的情况
	const char* const AS_REPORT_ATTR_RAWURL = "as.report.attr.raw_url";
	//mid
	const char* const AS_REPORT_ATTR_RAWMID = "as.report.attr.raw_mid";
	//上报的内容,binary
	const char* const AS_REPORT_ATTR_CONTENT = "as.report.attr.content";
	//上报类型,不能为空,utf8 string
	const char* const AS_REPORT_ATTR_TYPE = "as.report.attr.type";
	//同步上报的超时间隔,单位为秒,int
	const char* const AS_REPORT_ATTR_SYNCTIMEOUT = "as.report.attr.sync_timeout";
	//上报建立的连接设置keepalived属性
	const char* const AS_REPORT_ATTR_KEEPALIVE = "as.report.attr.keepalive";
	//是否需要merge,用于upload_client_log接口的内容按指定大小和时间合并的逻辑
	const char* const AS_REPORT_ATTR_MERGE = "as.report.attr.merge";
	//上传文件路径
	const char* const AS_REPORT_ATTR_CONTENT_TYPE = "as.report.attr.content_type";
	//HTTP 请求头 格式key1:val1\r\nkey2:val2\r\nkey3:val3
	const char* const AS_REPORT_ATTR_HTTPHEADER = "as.report.attr.http_header";
	//服务端返回的httpCode,int
	const char* const AS_REPORT_ATTR_SERVRET_CODE = "as.report.attr.servret.code";
	//服务端返回的内容,binary
	const char* const AS_REPORT_ATTR_SERVRET_BUFFER = "as.report.attr.servret.buffer";

	//////////////////////////////////////////////////////////////////////////
	//report模块自身的各种属性声明,属性统一为utf8字符串
	//reportcom的运行模式，std_server模式会真正调用netagent的接口做上报,std_client模式时发给server进程来上报
	const char* const AS_REPORTCOMATTR_RUNTYPE = "as.reportcom.attr.run_mode";
	const char* const AS_REPORTCOMATTR_STDSERVERMODE = "as.reportcom.attr.std_server_mode";
	const char* const AS_REPORTCOMATTR_STDCLIENTMODE = "as.reportcom.attr.std_client_mode";
	//////////////////////////////////////////////////////////////////////////
	const int ASReportMethod_HttpGET = 0;
	const int ASReportMethod_HttpPost = 1;
	const int ASReportTimeout_Default = 1;

	const int ASReportContentType_Buffer = 0;
	const int ASReportContentType_File = 1;
	const char* const AS_REPORT_LOG_FILTER = "as.log.reportcom";
};

#endif // ASReportCom_h
