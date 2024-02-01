//
//  ASContentClass.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASContentClass_h
#define ASContentClass_h

//预置的一些content_provider的class
namespace ASContentClass
{
	//////////////////////////////////////////////////////////////////////////
	//netagnet_info,保存通讯相关的各种信息,这些content都是astring类型,utf-8编码
	const char* const AS_CONTENT_CLASS_NETAGENTINFO = "as.content.class.netagent_info";
	//当前机器的mid
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_MID = "mid";
	//和控制中心联通性，1为正常连接0为断开, char
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CONNECTSTATUS = "connnect_status";
	//外网联通性，1为正常连接0为断开, char
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_INTERNETSTATUS = "internet_status";
	//控制中心地址,ip:port的格式,可能是域名
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CONTROLCENTERADDR = "controlcenter_addr";
	//从svr_init_info.json获取的client_id
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CLIENT_ID = "client_id";
	//从svr_init_info.json获取的ccid
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CCID = "ccid";
	//终端类型,winc|wins等
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CLIENTTYPE = "client_type";
	//终端类型,winc|wins等,用数字表示,int
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CLIENTTYPENUM = "client_type_num";
	//终端当前剩余可用连接数, int
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_REMAIN_CONNECTIONS = "remain_connections";
	//终端当前剩余的可用流量, int, bytes/second
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_REMAIN_FLOWS = "remain_flows";
	//上次心跳内容, char
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_HEARTBEAT_CONTENT = "heartbeat_content";
	//最近一次心跳的时间戳，char
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_Heartbeat_Timestamp = "heartbeat_timestamp";
	//netagent的oem配置文件的同步属性, int, 1为占用，0为非占用，目前只用于FrameworkMisc的同步
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CONF_HANDLE_STATUS = "confhandle_status";
#ifdef __linux__
	//linux版agent特有的属性，linux终端的标识
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_LINUX_UUID = "linux_uuid";
	//linux版基于IPV6特有的属性，linux通信网卡名称
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_ETH_NAME = "eth_name";
	//linux版区分有无界面特有的属性，linux界面标示，1为有界面，0为无界面
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_FRONT_UI = "ui_status";
#endif
	//netagent提供的本机进行通讯的ip地址, char
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_Local_ReportIp = "local_reportip";
	//netagent提供的get_client_info接口返回信息，bundle的查询key前缀，实际使用时候的key=prefix+节点名，如clientinfo.dlp_uuid, char
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CLIENTINFO_PREFIX = "clientinfo.";
	//dlp用户名
	const char* const AS_CONTENT_VALUE_NETAGENTINFO_CLIENTINFO_dlpuser = "clientinfo.dlp_user";

	//////////////////////////////////////////////////////////////////////////
	//framework_info，保存framework的基础信息    
	const char* const AS_CONTENT_CLASS_FRAMEWORKINFO = "as.content.class.framework_info";
	const char* const AS_CONTENT_VALUE_FRAMEWORKINFO_SVCREADY = "svcready";
};

#endif /* ASContentClass_h */

