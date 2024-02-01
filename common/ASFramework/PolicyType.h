#ifndef __POLICY_TYPE_H__
#define __POLICY_TYPE_H__

enum PolicyType
{
	//1000开头的为体检和查杀相关
	//PolicyType_EXAM_NOFIX          = 1000,//暂时用不上，先屏蔽
	//PolicyType_EXAM_FIXSPECIFIC    = 1001,//暂时用不上，先屏蔽
	//PolicyType_EXAM_FIXALL         = 1002,//暂时用不上，先屏蔽
	PolicyType_EXAM_SCAN			 = 1200,//体检扫描
	//PolicyType_EXAM_FIXSPECIFIC2	 = 1201,//暂时用不上，先屏蔽

	PolicyType_Plugin_Scan   = 1202,//插件扫描
	PolicyType_Plugin_Fix    = 1203,//插件处理,修复/信任等

	PolicyType_SysRepire_Scan = 1204,//系统修复扫描
	PolicyType_SysRepire_Fix  = 1205,//系统修复项处理

	PolicyType_Speedup_Scan = 1206,//开机加速扫描
	PolicyType_Speedup_Fix  = 1207,//开机加速处理

	//跟体检没关系，可还是放在一起吧
	PolicyType_REMOVE_QUARANT_ITEM	 = 1300,//删除隔离区特定项
	PolicyType_REMOVE_TRUST_ITEM	 = 1301,//删除信任区特定项
	
	//跟体检无关，但也是1000开头

	//1100开头的为漏洞修复相关
	PolicyType_LEAK_FIX     = 1100,//漏洞修复
	PolicyType_LEAK_IGNORE     = 1101,//漏洞忽略
	PolicyType_LEAK_SCAN       = 1102,//漏洞扫描
	PolicyType_CANCEL_FIX	   = 1110,//取消修复
	PolicyType_CANCEL_IGNORE   = 1111,//取消忽略
	PolicyType_LEAK_REPAIR	   = 1109,//新增漏洞策略唯一标识
	
	PolicyType_VIRUS_SCAN    = 1600,//查杀病毒
	PolicyType_QUARANT_RESTORE = 1601,//隔离区相关

	//2000开头的为设置相关
	PolicyType_CLIENT_CONFIG = 2100,//终端设置

	//21xx的为单终端或非组策略的设置，通过task通道下发的
	PolicyType_CLIENT_CONFIG_WS		= 2101, //卫士模块终端设置
	PolicyType_CLIENT_CONFIG_SD		= 2102, //杀毒模块终端设置
	PolicyType_CLIENT_CONFIG_XP_FIX = 2103, //盾甲模块终端设置

	PolicyType_NETFLOW       = 2200,//流量管控
	PolicyType_DEVICE        = 2300,//外设管理
	PolicyType_CONFIG			= 2600,//终端管控全局配置
	PolicyType_HARDWARE			= 2602,//硬件信息
	PolicyType_NETWORK			= 2604,//网络配置
	PolicyType_DEVICE_NEW		= 2606,//外设策略
	PolicyType_INTERNET			= 2608,//网络防护策略
	PolicyType_NETDEFEND        = 2610,//网络防护策略
	PolicyType_DESKTOPENFORCER	= 2612,//桌面加固策略
	PolicyType_PROCESS			= 2614,//进程控制策略
	PolicyType_UDISK			= 2616,//U盘管理
	PolicyType_OSINFO			= 2618, //操作系统配置信息
	PolicyType_HARD_Temperature	= 2620,//硬件温度
	PolicyType_DEVICE_Exclude	= 2622,//硬件例外
	PolicyType_ANTIVIRUS        = 2624, //杀毒软件
	PolicyType_OSDETAIL			= 2626, //操作系统详情
	PolicyType_NETFIND			= 2628, //终端发现
	PolicyType_GetCert			= 2629,	//查询证书
	PolicyType_GetRegistry		= 2630,	//查询注册表

	PolicyType_EDR		= 2650,	//EDR操作命令

	PolicyType_CMDNAC			= 2700, //准入命令

	//3000开头的为软件管理相关
	PolicyType_SPEEDUP       = 3100,//开机加速
	PolicyType_SOFTPUSH      = 3200,//软件分发
	PolicyType_SOFTUNINST    = 3300,//发布软件卸载通知
	PolicyType_WHITEHATTOOL =3400,//白帽软件运行


	//4000开头的为其他的任务
	PolicyType_MESSAGE       = 4100,//发布公告
	PolicyType_MMBIND		=4101,//终端人机信息绑定
	PolicyType_PFS_TOOL      = 4200,//病毒专杀
	PolicyType_CLIENT_UPDATE = 4300,//终端升级
    PolicyType_FILE_LEVEL    = 4400,//文件吊销
	PolicyType_FILE_LEVELAD    = 4401,//文件吊销ad
	PolicyType_WRITE_EXT    = 4402,//写后缀名

	PolicyType_TRUST_URL = 4500,	//信任网址白名单

	PolicyType_MIGRATE      = 4700,//终端迁移

	PolicyType_REMOTE_DESKTOP = 4800,//远程桌面

    PolicyType_CANCEL        = 5000,//策略取消

	PolicyType_Max	= 15000
};

#endif
