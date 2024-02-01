//
//  ASFrameworkProperty.h
//  ASFrameworkProperty
//
//  Created by houfengjie on 16/11/10.
//  Copyright ? 2016年 qihoo. All rights reserved.
//

#ifndef ASFrameworkProperty_h
#define ASFrameworkProperty_h

namespace ASFrameworkProperty
{
	//终端通讯协议
	const char* const AS_FRAMEWORK_PROPERTY_PROTOCOL = "net_protocol";
	//终端心跳间隔
	const char* const AS_FRAMEWORK_PROPERTY_HEARTINTERNAL = "ping_time";
	//终端注册间隔
	const char* const AS_FRAMEWORK_PROPERTY_REGISTERINTERNAL = "update_client_info";
	//终端负载均衡服务器地址
	const char* const AS_FRAMEWORK_PROPERTY_UPSTREAMSETTING = "upstream_setting";
	//终端长连接服务器地址
	const char* const AS_FRAMEWORK_PROPERTY_LONGLINKSVRADDR = "persistent_connetion";
	//终端外网探测间隔
	const char* const AS_FRAMEWORK_PROPERTY_INTERNETCHECKINTERNAL = "internet_check_interval";
	//终端上报最大连接数
	const char* const AS_FRAMEWORK_PROPERTY_MAXLOGCONNECTION = "max_concurrent";
	//终端上报最大出口流量
	const char* const AS_FRAMEWORK_PROPERTY_MAXLOGFLOWSECOND = "max_speed";
	//终端上报时间限制
	const char* const AS_FRAMEWORK_PROPERTY_LOGREPORTLIMITTIME = "limit_time_list";
};

#endif