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

namespace ASReportCom
{
	//////////////////////////////////////////////////////////////////////////
	//上报数据的属性,Report接口的IASBundle参数里保存
	//是否关键数据,1为关键0非关键,int
	const char* const AS_REPORT_ATTR_CRITICAL = "as.report.attr.critical";
	//是否同步上报,int,1为同步上报0为异步
	const char* const AS_REPORT_ATTR_SYNC = "as.report.attr.synchronous";
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
	//是否需要merge,用于upload_client_log接口的内容按指定大小和时间合并的逻辑
	const char* const AS_REPORT_ATTR_MERGE = "as.report.attr.merge";
	//服务端返回的httpCode,int
	const char* const AS_REPORT_ATTR_SERVRET_CODE = "as.report.attr.servret.code";
	//服务端返回的内容,binary
	const char* const AS_REPORT_ATTR_SERVRET_BUFFER = "as.report.attr.servret.buffer";

	//////////////////////////////////////////////////////////////////////////
	const int ASReportMethod_HttpGET = 0;
	const int ASReportMethod_HttpPost = 1;
	const int ASReportTimeout_Default = 1;
};

#endif // ASReportCom_h