//
//  ASNetAgentConfKey.h
//  ASFrameworkProperty
//
//  说明：用于FrameworkMisc.dll修改Agent的配置文件
//
//  Created by houfengjie on 16/11/10.
//  Copyright ? 2016年 qihoo. All rights reserved.
//

#ifndef ASNetAgentConfKey_h
#define ASNetAgentConfKey_h

//这里定义了asnetagent.conf里配置项的key
namespace ASNetAgentConfKey
{
	//日志相关
	const char* const AS_NETAGENT_CONFKEY_LOG_LEVEL = "log_level";
	const size_t AS_NETAGENT_VALUE_DEFAULT_LOG_LEVEL = 2;
	const char* const AS_NETAGENT_CONFKEY_LOG_SIZE = "log_size";
	const size_t AS_NETAGENT_VALUE_DEFAULT_LOG_SIZE = 10*1024*1024;	//10MB

	//netaddr_setting，网络地址相关
	const char* const AS_NETAGENT_CONFKEY_NETADDR_SETTING = "netaddr_setting";
	const char* const AS_NETAGENT_CONFKEY_CONTROL_CENTER = "control_center";
	const char* const AS_NETAGENT_CONFKEY_CONTROL_CENTER_IPV6 = "control_center_ipv6";
	const char* const AS_NETAGENT_CONFKEY_SVR_INIT_INTERVAL = "svr_init_interval";
	const size_t AS_NETAGENT_VALUE_DEFAULT_SVR_INIT_INTERVAL = 3*3600;	//3hours

	//register_setting，注册相关
	const char* const AS_NETAGENT_CONFKEY_REGISTER_SETTING = "register_setting";
	const char* const AS_NETAGENT_CONFKEY_REGISTER_INTERVAL = "interval"; //注册的默认间隔，单位为秒
	const size_t AS_NETAGENT_VALUE_DEFAULT_REGISTER_INTERVAL = 3600;
	const char* const AS_NETAGENT_CONFKEY_REGISTER_INTERVAL_ONFAIL = "interval_onfail"; //注册的失败时的重试间隔，单位为秒
	const size_t AS_NETAGENT_VALUE_DEFAULT_REGISTER_INTERVAL_ONFAIL = 10;
	const char* const AS_NETAGENT_CONFKEY_REGISTER_MAX_RETRY_ONFAIL = "max_retry_times_onfail";//注册失败时的重试次数
	const size_t AS_NETAGENT_VALUE_DEFAULT_REGISTER_MAX_RETRY_ONFAIL = 10;

	//quota_setting,配额（带宽）设置相关
	const char* const AS_NETAGENT_CONFKEY_QUOTA_SETTING = "quota_setting";
	const char* const AS_NETAGENT_CONFKEY_MAX_CONNECTION = "max_connection";
	const size_t AS_NETAGENT_VALUE_DEFAULT_MAX_CONNECTION = 100;
	const char* const AS_NETAGENT_CONFKEY_MAX_FLOW_PERSECOND = "max_flow_per_second"; //默认每秒最大流量，单位为Byte
	const size_t AS_NETAGENT_VALUE_DEFAULT_MAX_FLOW_PERSECOND = 10;
	const char* const AS_NETAGENT_CONFKEY_LIMIT_TIME_LIST = "limit_time_list";

	//short_link,短连接相关
	const char* const AS_NETAGENT_CONFKEY_SHORTLINK = "short_link";
	const char* const AS_NETAGENT_CONFKEY_HEART_INTERVAL = "heart_interval"; //心跳的默认间隔，单位为秒
	const size_t AS_NETAGENT_VALUE_DEFAULT_HEART_INTERVAL = 10;
	const char* const AS_NETAGENT_CONFKEY_INCREASE_ONFAIL = "increase_on_fail"; //心跳的失败时的增加间隔，单位为秒
	const size_t AS_NETAGENT_VALUE_DEFAULT_INCREASE_ONFAIL = 10;
	const char* const AS_NETAGENT_CONFKEY_MAX_HEART_INTERVAL = "max_heart_interval"; //心跳最大间隔
	const size_t AS_NETAGENT_VALUE_DEFAULT_MAX_HEART_INTERVAL = 3600;
	const char* const AS_NETAGENT_CONFKEY_NET_PROTOCOL = "net_protocol"; ////终端通讯协议，默认1.0
	const char* const AS_NETAGENT_CONFKEY_DELAY_CONNECT = "delay_connect";
	//long_link,长连接相关
	const char* const AS_NETAGENT_CONFKEY_LONGLINK = "long_link";
	const char* const AS_NETAGENT_CONFKEY_LONGLINK_ENABLE = "enable";
	const char* const AS_NETAGENT_CONFKEY_LONGLINK_SVRADDR = "svr_addr";
	const size_t AS_NETAGENT_VALUE_DEFAULT_Longlink_Hearbeat_Interval_Minimum = 3*60*60;	//启用长连接后的心跳间隔最小值，单位秒

	//upstream_setting，负载均衡相关
	const char* const AS_NETAGENT_CONFKEY_UPSTREAM_SETTING = "upstream_setting";
	const char* const AS_NETAGENT_CONFKEY_MATCH_TYPE = "match_type";
	const char* const AS_NETAGENT_VALUE_DEFAULT_MATCH_TYPE = "stable_random";
	const char* const AS_NETAGENT_CONFKEY_SERVER_LIST = "server_list";
	const size_t AS_NETAGENT_VALUE_DEFAULT_UPSTREAM_RESELECT_INTERVAL = 3 * 3600; //upstream server重选的默认间隔，单位为秒

	//migrate_task, 迁移任务相关
	const char* const AS_NETAGENT_CONFKEY_MIGRATE_TASK = "migrate_task";
	const char* const AS_NETAGENT_CONFKEY_TASK_DETAIL = "task_detail";
	const char* const AS_NETAGENT_CONFKEY_TASK_FINISH = "task_finish";

	//clientinfo 终端信息获取接口get_client_info.json接口相关
	const char* const AS_NETAGENT_CONFKEY_CLIENT_INFO			= "client_info";
	const char* const AS_NETAGENT_CONFKEY_CLIENT_INFO_INTERVAL	= "interval";
	const char* const AS_NETAGENT_CONFKEY_CLIENT_INFO_POSTBODY	= "post_body";
	const char* const AS_NETAGENT_CONFKEY_CLIENT_INFO_VER		= "client_info_ver";
	const size_t AS_NETAGENT_VALUE_DEFAULT_CLIENT_INFO_INTERVAL	= 3*60*60;	//接口的轮询周期

	//internet check 外网探测
	const char* const AS_NETAGENT_CONFKEY_INTERNET_CHECK = "internet_check";
	const char* const AS_NETAGENT_CONFKEY_INTERNET_CHECK_ENABLE = "enable";//启用终端外网探测的开关，默认为true
	const char* const AS_NETAGENT_CONFKEY_INTERNET_CHECK_INTERVAL = "interval";//终端外网探测间隔,单位为秒
	const size_t AS_NETAGENT_VALUE_DEFAULT_INTERNET_CHECK_INTERVAL = 900;

	//skip mode 跳过业务设置，适用于单机版等跳过注册、心跳等业务，默认为0x0，即所有业务正常，重启生效
	const char* const AS_NETAGENT_CONFKEY_SKIP_MODE = "skip_mode";
};

#endif //ASNetAgentConfKey_h
