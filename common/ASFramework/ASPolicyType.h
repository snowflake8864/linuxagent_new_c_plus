//
//  as_policy_type.h
//  asframework
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef as_policy_type_h
#define as_policy_type_h

namespace ASTaskType
{
	//////////////////////////////////////////////////////////////////////////
	//控制台任务的定义

	//1000开头的为体检和查杀相关
	//	const long ASTaskType_EXAM_NOFIX          = 1000,//暂时用不上，先屏蔽
	//	const long ASTaskType_EXAM_FIXSPECIFIC    = 1001,//暂时用不上，先屏蔽
	//	const long ASTaskType_EXAM_FIXALL         = 1002,//暂时用不上，先屏蔽
	const long ASTaskType_EXAM_SCAN			 = 1200;//体检扫描
	//	const long ASTaskType_EXAM_FIXSPECIFIC2	 = 1201,//暂时用不上，先屏蔽

	const long ASTaskType_Plugin_Scan   = 1202;//插件扫描
    const long ASTaskType_Plugin_Fix    = 1203;//插件处理,修复/信任等
    const long ASTaskType_SysRepire_Scan = 1204;//系统修复扫描
    const long ASTaskType_SysRepire_Fix  = 1205;//系统修复项处理
    const long ASTaskType_Speedup_Scan = 1206;//开机加速扫描
    const long ASTaskType_Speedup_Fix  = 1207;//开机加速处理

	//跟体检没关系，可还是放在一起吧
    const long ASTaskType_REMOVE_QUARANT_ITEM	 = 1300;//删除隔离区特定项
    const long ASTaskType_REMOVE_TRUST_ITEM	 = 1301;//删除信任区特定项

	//跟体检无关，但也是1000开头

	//1100开头的为漏洞修复相关
    const long ASTaskType_LEAK_FIX     = 1100;//漏洞修复
    const long ASTaskType_LEAK_IGNORE     = 1101;//漏洞忽略
    const long ASTaskType_LEAK_SCAN       = 1102;//漏洞扫描
    const long ASTaskType_CANCEL_FIX	   = 1110;//取消修复
    const long ASTaskType_CANCEL_IGNORE   = 1111;//取消忽略
    const long ASTaskType_LEAK_REPAIR	   = 1109;//新增漏洞策略唯一标识

	const long ASTaskType_INCIDENT_SCAN       =1220;//安全响应扫描任务
	const long ASTaskType_INCIDENT_DISPOSE    =1221;//安全响应处置任务

    const long ASTaskType_VIRUS_SCAN    = 1600;//查杀病毒
    const long ASTaskType_QUARANT_RESTORE = 1601;//隔离区相关

	const long ASTaskType_ClientConfig = 2100;
	
	//	//21xx的为单终端或非组策略的设置，通过task通道下发的
    const long ASTaskType_CLIENT_CONFIG_WS		= 2101; //卫士模块终端设置
    const long ASTaskType_CLIENT_CONFIG_SD		= 2102; //杀毒模块终端设置
    const long ASTaskType_CLIENT_CONFIG_XP_FIX = 2103; //盾甲模块终端设置
    const long ASTaskType_NETFLOW       = 2200;//流量管控
    const long ASTaskType_DEVICE        = 2300;//外设管理
    const long ASTaskType_CONFIG			= 2600;//终端管控全局配置
    const long ASTaskType_HARDWARE			= 2602;//硬件信息
    const long ASTaskType_NETWORK			= 2604;//网络配置
    const long ASTaskType_DEVICE_NEW		= 2606;//外设策略
    const long ASTaskType_INTERNET			= 2608;//网络防护策略
    const long ASTaskType_NETDEFEND        = 2610;//网络防护策略
    const long ASTaskType_DESKTOPENFORCER	= 2612;//桌面加固策略
    const long ASTaskType_PROCESS			= 2614;//进程控制策略
    const long ASTaskType_UDISK			= 2616;//U盘管理
    const long ASTaskType_OSINFO			= 2618; //操作系统配置信息
    const long ASTaskType_HARD_Temperature	= 2620;//硬件温度
    const long ASTaskType_DEVICE_Exclude	= 2622;//硬件例外
    const long ASTaskType_ANTIVIRUS        = 2624;//杀毒软件
    const long ASTaskType_OSDETAIL			= 2626; //操作系统详情
    const long ASTaskType_NETFIND			= 2628; //终端发现
	const long ASTaskType_GetCert			= 2629;	//查询证书
	const long ASTaskType_GetRegistry		= 2630;	//查询注册表
	
	const long ASTaskType_EDR				= 2650;	//EDR操作命令
	
	const long ASTaskType_FEEDBACK 			= 2660;//终端反馈
    const long ASTaskType_CMDNAC			= 2700; //准入命令
	const long ASTaskType_DLPChannel		= 2900; //DLP审批任务
	//3000开头的为软件管理相关
    const long ASTaskType_SPEEDUP       = 3100;//开机加速
    const long ASTaskType_SOFTPUSH      = 3200;//软件分发
    const long ASTaskType_SOFTUNINST    = 3300;//发布软件卸载通知
    const long ASTaskType_WHITEHATTOOL  = 3400;//白帽软件运行
	const long ASTaskType_SOFTUPDATE	= 3500;//软件升级
	const long ASTaskType_SOFTREPORT	= 3600;//软件上报


	//4000开头的为其他的任务
    const long ASTaskType_MESSAGE       = 4100;//发布公告
    const long ASTaskType_MMBIND		=4101;//终端人机信息绑定
    const long ASTaskType_ASSET_APPROVAL = 4120;//资产审批状态
    const long ASTaskType_PFS_TOOL      = 4200;//病毒专杀
    const long ASTaskType_CLIENT_UPDATE = 4300;//终端升级
	const long ASTaskType_UPDATE_ROLL_BACK     = 4301; //终端版本回退
    const long ASTaskType_FILE_LEVEL    = 4400;//文件吊销
    const long ASTaskType_FILE_LEVELAD    = 4401;//文件吊销ad
    const long ASTaskType_WRITE_EXT    = 4402;//写后缀名
    const long ASTaskType_TRUST_URL = 4500;	//信任网址白名单
    const long ASTaskType_MIGRATE      = 4700;//终端迁移
    const long ASTaskType_REMOTE_DESKTOP = 4800;//远程桌面
    const long ASTaskType_CANCEL        = 5000;//策略取消
	
	const long ASTaskType_Appctl        = 5001;//应用控制控制台白名单变更
	//6000-7000服务端内部使用，终端不要分配这些任务类型

    const long ASTaskType_Max	= 15000;


	//////////////////////////////////////////////////////////////////////////
	//控制台策略的定义,对应getconf里的conftype
	const char* const ASTaskType_Modularize = "md";
	const char* const ASTaskType_Sd = "sd";
	const char* const ASTaskType_Ws = "ws";
};

#endif //as_policy_type_h