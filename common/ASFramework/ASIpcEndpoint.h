//
//  ASIpcEndpoint.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASIpcEndpoint_h
#define ASIpcEndpoint_h

class IASIpcReceiver
{
public:
	virtual ASCode OnIpcMessage(IASBundle* pIpcData,IASBundle* pResult) = 0;
};

class IASBroadcastReceiver
{
public:
	virtual ASCode OnBroadcastMessage(IASBundle* pIpcData, IASBundle* pResult) = 0;
};

class IASIpcResultReceiver
{
public:
    virtual ASCode OnIpcResult(IASBundle* pIpcData, IASBundle* pIpcResultData) = 0;
};

__servicename(IASIpcEndpoint, "as.svc.ipcendpoint")
class IASIpcEndpoint : public IASFrameworkService
{
public:
    
	//注册注销感兴趣的消息类型，Bundle里应保存ASIPC_ATTR_MSGTYPE、ASIPC_ATTR_RECEIVERPOINTER
	virtual ASCode RegisterReceiver(IASOperaterBase* pOper,IASBundle* pData) = 0;
	virtual ASCode UnRegisterReceiver(IASOperaterBase* pOper,IASBundle* pData) = 0;

	//注册感兴趣的broadcast消息,bundle里必须保存ASIPC_ATTR_MSGTYPE、ASIPC_ATTR_BROADCASTRECEIVERPOINTER
	virtual ASCode RegisterBroadcastReceiver(IASOperaterBase* pOper, IASBundle* pData) = 0;
	virtual ASCode UnRegisterBroadcastReceiver(IASOperaterBase* pOper, IASBundle* pData) = 0;

	//发送ipc数据，bundle中应保存ASIPC_ATTR_MSGTYPE、ASIPC_ATTR_MSGCONT、ASIPC_ATTR_DESTINATION
    virtual ASCode SendIpc(IASOperaterBase* pOper, IASBundle* pIpcData) = 0;
	virtual ASCode SendBroadcast(IASOperaterBase* pOper, IASBundle* pIpcData) = 0;
    virtual ASCode SendIpcForResult(IASOperaterBase* pOper, IASBundle* pIpcData,IASBundle* pResultData) = 0;
    virtual ASCode SendIpcForResultAsync(IASOperaterBase* pOper, IASBundle* pIpcData,IASIpcResultReceiver* pResultData) = 0;

	//查询已经注册的endpoint
	//pInData可为空也可保存ASIPC_QUERY_REG_ENDPOINT_NAME、ASIPC_QUERY_REG_ENDPOINT_NAME_SUB其一
	//pOutData保存ASIPC_QUERY_REG_ENDPOINT_NAME_RESULT值，如果pInData=NULL，则返回所有已注册的endpoint的name
	virtual ASCode QueryRegisteredEndpoint(IASOperaterBase* pOper, IASBundle* pInData, IASBundle* pOutData) = 0;
};

namespace ASIpcEndpoint
{
	const long ASIPC_REPLYTIMEOUT_DEFAULT = 60;
	const char* const ASIPC_LOG_PREFIX = "as.log.ipc.";

	//////////////////////////////////////////////////////////////////////////
	//ipcendpoint自身的属性,统一为utf8字符串
	//ipcendpoint的名字
	const char* const ASIPC_ENDPOINT_ATTR_NAME 		= "as.ipc.endpoint.attr.name";
	//ipcendpoint创建者的名字
	const char* const ASIPC_ENDPOINT_ATTR_OWNERNAME = "as.ipc.endpoint.attr.ownername";
	//ipcendpoint创建者的全路径
	const char* const ASIPC_ENDPOINT_ATTR_OWNERPATH 	= "as.ipc.endpoint.attr.ownerpath";	

	//////////////////////////////////////////////////////////////////////////
	//ipc消息的属性
	//消息发送者，utf-8字符串
	const char* const ASIPC_ATTR_SOURCE				= "as.ipc.attr.source";
	//消息类型，utf-8字符串
	const char* const ASIPC_ATTR_MSGTYPE			= "as.ipc.attr.msgtype";
	//消息内容，binary
	const char* const ASIPC_ATTR_MSGCONT			= "as.ipc.attr.msgcont";
	//消息内容长度，int
	const char* const ASIPC_ATTR_MSGCONTLEN			= "as.ipc.attr.msgcontlen";
	//是否需要回应，int
	const char* const ASIPC_ATTR_NEEDREPLY			= "as.ipc.attr.need_reply";
	//回应的超时时间，单位为秒，int
	const char* const ASIPC_ATTR_REPLYTIMEOUT		= "as.ipc.attr.reply_timeout";
	//消息发送目标，utf-8字符串，group_name.endpoint_name的格式，group_name可为空，表示发给默认组
	const char* const ASIPC_ATTR_DESTINATION		= "as.ipc.attr.destination";
	//接收者指针，IASIpcReceiver*类型的binary
	const char* const ASIPC_ATTR_RECEIVERPOINTER	= "as.ipc.attr.receiver_pointer";
	//接收者指针，IASBroadcastReceiver*类型的binary
	const char* const ASIPC_ATTR_BROADCASTRECEIVERPOINTER = "as.ipc.attr.broadcastreceiver_pointer";
	//消息序列号，内部使用，utf-8字符串
	const char* const ASIPC_ATTR_SERIALNO			= "as.ipc.attr.serial_no";
	//ipc消息是否是broadcast，内部使用
	const char* const ASIPC_ATTR_ISBROADCAST		= "as.ipc.attr.is_broadcast";

	////////////////////////////////////////////////////////////////////////////
	//精确查询指定endpoint是否已经注册，utf-8字符串，不区分大小写
	const char* const ASIPC_QUERY_REG_ENDPOINT_NAME			= "as.ipc.query.reg.endpoint_name";
	//查询包含指定字符串的endpoint是否已经注册，utf-8字符串，不区分大小写
	const char* const ASIPC_QUERY_REG_ENDPOINT_NAME_SUB		= "as.ipc.query.reg.endpoint_name_sub";
	//endpoint注册状态查询结果，如果未注册，结果为空，如果已注册则返回endpoint的名字，如有多个则用分号分隔，utf-8字符串
	const char* const ASIPC_QUERY_REG_ENDPOINT_NAME_RESULT	= "as.ipc.query.reg.endpoint_name_result";

	//ipc消息处理结果的属性
	//是否超时，int
	const char* const ASIPC_RESULT_ISTIMEOUT		= "as.ipc.result.is_timeout";
	//ipc result,int(1成功0失败)
	const char* const ASIPC_RESULT_VALUE			= "as.ipc.result.value";
	//ipc result详情，char字符串
	const char* const ASIPC_RESULT_DETAIL			= "as.ipc.result.detail";

#ifdef _WINDOWS
	const char* const AS_IPC_COMPONENT_NAME = "ASIpcEndpoint.dll";
	const char* const AS_IPC_COMPONENT_PATH = "EntClient\\ASIpcEndpoint.dll";

	const char* const AS_IPC_COMPONENT_NAMEx64 = "ASIpcEndpoint64.dll";
	const char* const AS_IPC_COMPONENT_PATHx64 = "EntClient\\ASIpcEndpoint64.dll";
#endif	
};

typedef IASIpcEndpoint* (__stdcall FCreateASIpcEndpoint)(IASOperaterBase* lpOperator,const char* lpszEndpointName);
extern "C" IASIpcEndpoint* __stdcall CreateASIpcEndpoint(IASOperaterBase* lpOperator, const char* lpszEndpointName);

#endif /* ASIpcEndpoint_h */

