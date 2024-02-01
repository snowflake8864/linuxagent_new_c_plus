//
//  ASIpcTypes.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASIpcTypes_h
#define ASIpcTypes_h

namespace ASIpcTypes
{
	//////////////////////////////////////////////////////////////////////////
	//ipc端点定义,在这里声明自己要注册的ipc端点,理论上进程内有默认的ipcendpoint,不用自己注册
	//这里大多是兼容1.0时代的老插件
	const char* const ASIpcEndpoint_osecSafe = "osecsafe.exe";
	const char* const ASIpcEndpoint_osecSafeLinux = "osecsafed";

	//////////////////////////////////////////////////////////////////////////
	//升级类ipc通知的消息类型定义
	//检查更新通知的ipc类型,目前osecsafe界面的检测更新按钮用到
	const char* const ASIpcType_CheckUpdate = "as.ipc.type.update.check_update";
	//升级某个模块
	const char* const ASIpcType_CheckModuleUpdate = "as.ipc.type.update.check_module_update";
	//检测更新取消,osecsafe界面的检测更新取消按钮用到
	const char* const ASIpcType_CheckUpdateCancel = "as.ipc.type.update.check_update_cancel";
	//模块升级完成,从这里可以获取到模块名,升级的文件列表等信息,消息内容类似json:{ "src":"1.ext","module":"xpfix","result":"1","files":"osecros.dll,xpfix.exe" }
	const char* const ASIpcTypeModuleUpdateFinish = "as.ipc.type.update.module_update_finish";
	const char* const ASIpcTypeModuleUpdateBegin = "as.ipc.type.update.module_update_begin";
	//模块升级完成,从这里可以获取到模块名,升级的文件列表等信息,消息内容类似json:{ "src":"1.ext","module":"xpfix","result":"1","files":"osecros.dll,xpfix.exe" }
	const char* const ASIpcTypeUpdateBegin = "as.ipc.type.update.update_begin";
	const char* const ASIpcTypeUpdateFinish = "as.ipc.type.update.update_finish";
	const char* const ASIpcTypePostModularize = "as.ipc.type.post_modularize";	
	//触发asnetagent心跳一次，消息内容类似{"src": "osecsafe.exe","data": {"value": "1"}}
	const char* const ASIpcTypeAgentInvokeHeartBeat = "as.ipc.type.invoke_heartbeat";
	//asnetagent的最近一次的心跳结果，消息内容类似{"src": "asnetagent","data": {"result":"1","httpcode":"200/304"}}
	const char* const ASIpcTypeAgentHeartBeatResult = "as.ipc.type.heartbeat_result";
	//触发小助手重启消息{"cmd":"restart"}
	const char* const ASIpcTypeRestartEntClient = "as.ipc.type.restart_entclient";
	//通知asnetagent迁移到指定的server，消息内容类似{"src":"EntSGCCAntivirus.ext", "server":"127.0.0.1:80", "type": 0/1} 0--mgr, 1--upd
	const char* const ASIpcTypeAgentModifyServer = "as.ipc.type.modify_server";
    //数据采集中心 接收采集点消息类型
	const char* const ASIpcTypeDcCollect = "as.ipc.type.dc.ipccenter";	
	//实名认证 tray与小助手 ipc通信弹窗使用
	const char* const ASIpcTypeInvokeBindPopup = "as.ipc.type.bind.invoke_bind_popup";
	//激活数据 LocalConfig.exe通知EntClientActive.ext插件
	const char* const ASIpcTypeActiveClient = "as.ipc.type.active_client";
	//防火墙小助手 EntClientFwSubscribe.ext 消息通知
	const char* const ASIpcType_Policy_osecEntFw_Commune = "as.ipc.type.framework.osecentfw";
	//session变化通知 ASFrameworkMisc.dll接收服务进程消息后通知用户进程组件
	const char* const ASIpcType_Session_Signal = "as.ipc.type.session_signal";

	//////////////////////////////////////////////////////////////////////////
	//framework内部使用的ipc端点定义,勿动!!!
	const char* const ASIpcEndpoint_Framework_StdSrv = "framework-std_srv";
	const char* const ASIpcEndpoint_Framework_StdClient = "framework-std_client";
	const char* const ASIpcEndpoint_Framework_OuterClient = "framework-outer_client";
	const char* const ASIpcEndpoint_Framework_3rdOuterClient = "framework-3rd_outer_client";

	//////////////////////////////////////////////////////////////////////////
	//framework内部使用的ipc类型定义,勿动!!!
	//内部约定,某个type的msg如果需要回应,则回应的消息type为原类型加上reply后缀
	const char* const ASIpcType_ReplySuffix = "_reply";

	//contentprovider之间的查询,内部使用
	const char* const ASIpcType_ContentQuery = "as.ipc.type.framework.content_query";
	const char* const ASIpcType_ContentQueryReply = "as.ipc.type.framework.content_query_reply";
	//设置contentprovider提供的属性,内部使用
	const char* const ASIpcType_ContentUpdate = "as.ipc.type.framework.content_update";
	const char* const ASIpcType_ContentUpdateReply = "as.ipc.type.framework.content_update_reply";
	//通过ipc做日志上报时的消息类型,内部使用
	const char* const ASIpcType_ReportCommune = "as.ipc.type.framework.report_commune";
	const char* const ASIpcType_ReportCommuneReply = "as.ipc.type.framework.report_commune_reply";

	//通过ipc做日志上报时的消息类型,内部使用
	const char* const ASIpcType_NetFlowApply = "as.ipc.type.framework.netflow_apply";

	//通过ipc做策略派发时的消息类型,内部使用
	const char* const ASIpcType_Policy_ServerToClient_Commune = "as.ipc.type.framework.policy_server_to_client_commune";
	const char* const ASIpcType_Policy_ServerToClient_CommuneReply = "as.ipc.type.framework.policy_server_to_client_commune_reply";
	const char* const ASIpcType_Policy_ClientToServer_Commune = "as.ipc.type.framework.policy_client_to_server_commune";
	const char* const ASIpcType_Policy_ClientToServer_CommuneReply = "as.ipc.type.framework.policy_client_to_server_commune_reply";

	//设置getconf传入的mid,目前为建行设置
	const char* const ASIpcType_Policy_RefleshGetConfMid = "as.ipc.type.framework.reflesh_getconf_mid";

	//登陆登出事件通知policy
	const char* const ASIpcType_Policy_EventChangeNotify = "as.ipc.type.framework.policy_event_change_notify";
	//登陆登出事件通知netagent
	const char* const ASIpcType_NetAgent_EventChangeNotify = "as.ipc.type.framework.netagent_event_change_notify";
	//用户注销依然派发用户策略类型
	const char* const ASIpcType_Policy_LogoutKeepUserPolicySetting = "as.ipc.type.framework.policy_logout_keep_userpolicy_setting";
	//安检合规事件结果通知policy {"source":"StartEntSecurityCheck.exe", "nac_policy_id":1, "security_result":0}
	const char* const ASIpcType_Policy_SecurityCheckEvent = "as.ipc.type.framework.policy.security_check";

	//软件分发执行动作通知用户抉择
	const char* const ASIpcType_SoftDispatch_EventNotify = "as.ipc.type.framework.soft_dispatch_event_notify";
	const char* const ASIpcType_SoftDispatch_RecieveEvent = "as.ipc.type.framework.soft_dispatch_recieveEvent";

	//自保开关
	const char* const ASIpcType_SelfProtected_Switch = "as.ipc.type.framework.self_protected_switch";

	//自动升级配置
	const char* const ASIpcType_AutoUpdate_EventNotify = "as.ipc.type.framework.auto_update_event_notify";

	//资产登记
	const char* const ASIpcType_AssetRegister_InfoQuery = "as.ipc.type.framework.asset_register_query_info";
	const char* const ASIpcType_AssetRegister_SetInfo = "as.ipc.type.framework.asset_register_set_info";
	const char* const ASIpcType_AssetRegister_GetConf = "as.ipc.type.framework.asset_register_get_conf";
	const char* const ASIpcType_AssetRegister_GetClientGroupList = "as.ipc.type.framework.asset_register_get_client_group_list";
	const char* const ASIpcType_AssetRegister_GetUserGroupList = "as.ipc.type.framework.asset_register_get_user_group_list";
	const char* const ASIpcType_AssetRegister_GetUserListByGroupID = "as.ipc.type.framework.asset_register_get_use_list_by_group_id";

	//终端外观定制
	const char* const ASIpcType_TerminalSet_EventNotify = "as.ipc.type.framework.terminal_set_event_notify";

	//查询当前系统空闲状态
	const char* const ASIpcType_Query_System_Idle_Status = "as.ipc.type.framework.query_system_idle_status";
};

#endif /* ASIpcTypes_h */

