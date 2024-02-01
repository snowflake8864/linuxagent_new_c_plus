//
//  ASModularize.h
//  EntModularize
//
//  Created by dengfan on 16/4/14.
//  Copyright © 2016年 dengfan. All rights reserved.
//

#ifndef ASModularize_h
#define ASModularize_h

class IASModule : public IASBundle
{
public:

	virtual ASCode Install(IASOperaterBase* lpOperator) = 0;
	virtual ASCode Uninstall(IASOperaterBase* lpOperator) = 0;

	virtual ASCode Start(IASOperaterBase* lpOperator) = 0;
	virtual ASCode Stop(IASOperaterBase* lpOperator) = 0;
	virtual ASCode Update(IASOperaterBase* lpOperator,IN IASBundle* pAttrBundle,OUT IASBundle* pRltBundle = NULL) = 0;

	virtual long GetState(void) = 0;
	virtual bool CheckIntegrity(void) = 0;

	virtual const char* GetId(void) = 0;
	virtual const char* GetVersion(void) = 0;
};

class IASModUpdateCallback
{
public:
	//模块化升级时的回调接口,返回true继续升级,否则终止
	//开始升级,lpModLst为要升级的模块列表,逗号分隔
	virtual bool OnBeginUpdate(const char* lpModLst) { return true; }
	virtual bool OnBeginUpdateModule(const char* lpModID) { return true; }
	virtual bool OnEndUpdateModule(IASBundle* pResult) { return true; }
	virtual bool OnEndUpdate(IASBundle* pResult) { return true; }
};

#ifndef __servicename
#define __servicename(x,y) namespace ASFramework {const char* const AS_SVC_##x = y;};
#endif
__servicename(IASModuleMgr, "as.svc.modularizer")
class IASModuleMgr : public IASFrameworkService
{
public:
	
	virtual ASCode Init() = 0;
	virtual ASCode ReloadConf() = 0;
	virtual ASCode CreateInstance(IASOperaterBase* lpOperator, const char* clsid, void** ppInterface) = 0;
	
	virtual ASCode RegisterModule(IASOperaterBase* lpOperator, const char* lpszModuleId) = 0;
	virtual ASCode UnRegisterModule(IASOperaterBase* lpOperator, const char* lpszModuleId) = 0;
	
	virtual ASCode InstallModule(IASOperaterBase* lpOperator, const char* lpszModuleId) = 0;
	virtual ASCode UninstallModule(IASOperaterBase* lpOperator, const char* lpszModuleId) = 0;

	virtual long GetModuleState(IASOperaterBase* lpOperator, const char* lpszModuleId) = 0;
	virtual ASCode GetModuleIdList(IASOperaterBase* lpOperator, long lType,char* lpszBuffer,int* pBufLen) = 0;
	virtual IASModule* GetModuleById(IASOperaterBase* lpOperator, const char* lpszModuleId, bool bAutoCreate = true) = 0;

	virtual ASCode UpdateAll(IASOperaterBase* lpOperator, IASModUpdateCallback* pCallback = NULL) = 0;
	virtual ASCode UpdateModule(IASOperaterBase* lpOperator, const char* lpszModuleId, IASModUpdateCallback* pCallback = NULL) = 0;
	virtual ASCode UpdateByAttr(IASOperaterBase* lpOperator, IASBundle* lpAttrLst, IASModUpdateCallback* pCallback = NULL) = 0;
	virtual ASCode CheckUpdate(IASOperaterBase* lpOperator, long lUpdateType, IASModUpdateCallback* pCallback = NULL) = 0;
	virtual ASCode UnInit() = 0;
};

// 方便EntClientAir进程升级模块用的
class IASModUpdateHelper
{
public:
	virtual bool Init(void) = 0;
	virtual bool UpdateModule(const char* lpszModuleId) = 0;
	virtual bool UnInit() = 0;
};

typedef IASModUpdateHelper* (__stdcall fGetASModuleUpdHelper)();
#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) IASModUpdateHelper* (__stdcall GetASModuleUpdHelper)();
#endif

//ASUpdCore.dll导出的接口,这些接口非线程安全,请使用者注意!!!
class IASUpdateCore : public IASBundle
{
public:

	virtual ASCode Init() = 0;
	virtual ASCode CreateInstance(IASOperaterBase* lpOperator, const char* clsid, void** ppInterface) = 0;

	virtual ASCode UpdateByType(IASOperaterBase* lpOperator, long lUpdateType, IASBundle* pBundleResult = NULL, IASModUpdateCallback* pCallback = NULL) = 0;
	virtual ASCode UpdateByRule(IASOperaterBase* lpOperator, IASBundle* pBundleRule, IASBundle* pBundleResult = NULL, IASModUpdateCallback* pCallback = NULL) = 0;
	virtual ASCode UpdateModules(IASOperaterBase* lpOperator, const char* lpszModules, IASBundle* pBundleResult = NULL, IASModUpdateCallback* pCallback = NULL) = 0;
	virtual ASCode UnInit() = 0;

};

typedef IASUpdateCore* (__stdcall FCreateASUpdater)(IN IASFramework* pFramework,IN IASBundle* pParams);
#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) IASUpdateCore* __stdcall CreateASUpdater(IASFramework* pFramework, IASBundle* pParams);
#endif

namespace ASModuleMgrAttrKey
{
	// 升级的程序模块、病毒库、额外工具模块列表

	const char* const MODULARIZEKEY_NOIPC = "no_ipc";
	const char* const MODULARIZEKEY_RUNTYPE = "run_type";


	// 是否升级通过
	const char* const MODULARIZEKEY_UPDATECHECK = "check";
};

namespace ASModularize
{
	//////////////////////////////////////////////////////////////////////////
	//modulemgr的各种属性定义,属性统一为utf8字符串
	const char* const AS_MODMGR_ATTR_RUNTYPE = "as.modmgr.attr.run_type";
	const char* const AS_MODMGR_ATTR_NOIPC = "as.modmgr.attr.no_ipc";
	//core模式,这种模式下会接收模块化策略来安装卸载模块,还会处理升级逻辑
	const char* const AS_MODMGR_RUNTYPE_CORE = "as.modmgr.runtype.core";
	//container模式,这种模式下只是插件的容器,不会做额外逻辑
	const char* const AS_MODMGR_RUNTYPE_CONTAINER = "as.modmgr.runtype.container";
	//outer_client模式，这种模式下只提供升级相关接口，处理IPC消息
	const char* const AS_MODMGR_RUNTYPE_OUTER_CLIENT = "as.modmgr.runtype.outer_client";

	const char* const AS_MODULARIZE_LOG_FILTER = "as.log.modularize";
	const char* const AS_UPDCORE_LOG_FILTER = "as.log.upd_core";
	//是否正在升级过程中
	const char* const AS_MODMGR_ATTR_UPDATE_INPROGRESS = "as.modmgr.attr.update_inprogress";
	//升级相关的一些属性,依次为升级服务器地址,静态升级服务器,库升级模式
	const char* const AS_MODMGR_ATTR_UPDATESERVER = "as.modmgr.attr.update_server";
	const char* const AS_MODMGR_ATTR_STATICUPDATESERVER = "as.modmgr.attr.static_update_server";
	const char* const AS_MODMGR_ATTR_LIBUPDATE_MODE = "as.modmgr.attr.lib_update_mode";
    // 内部用的ipc指针，二进制
	const char* const AS_MODMGR_ATTR_IPCPOINTER = "as.modmgr.attr.ipc_pointer";

	//升级模式
	const char* const AS_MODMGR_ATTR_UPD_TYPE = "as.modmgr.attr.update_type";
	//升级规则
	const char* const AS_MODMGR_ATTR_UPD_RULE = "as.modmgr.attr.update_rule";
	
	//回退升级规则
	const char* const AS_MODMGR_UPD_RULE_ROLLBACK = "as.modmgr.update_rule.rollback";
	const char* const AS_MODMGR_UPD_ROLLBACK_FILE_PATH = "as.modmgr.rollback.filepath";


	const char* const AS_UPDATE_TIGGER_TYPE = "UpdateTiggerType";

	//是否不受优先分组的影响
	const char* const AS_UPDATE_NONEED_CHECK_ALLOW_UPGRADE = "NoNeedCheckUpgrade";

	//升级触发方式
	const long ASTigger_OnTime = 0; //定时升级
	const long ASTigger_Manual = 1; //手动升级
	const long ASTigger_Auto   = 2; //自动升级
	const long ASTigger_Task   = 4; //策略/任务升级
	const long ASTigger_Module = 5; //关键模块升级
	const long ASTigger_Unknown = 6;
	//模块类型,依次为所有,程序,库,扩展模块,补丁
	const long ASModuleType_All = 0;
	const long ASModuleType_Program = 1;
	const long ASModuleType_Lib = 2;
	const long ASModuleType_ExtAll = 3;
	const long ASModuleType_ExtProgram = 4;
	const long ASModuleType_ExtLib = 5;
	const long ASModuleType_Leak = 6;

	//升级模式,依次为未知|程序升级(全部升级)|库升级|不自动升级|定时升级|模块升级|补丁库升级|主程序升级|病毒库和补丁库
	const long ASUpdateType_Unknown = 0;
	const long ASUpdateType_All = 1;
	const long ASUpdateType_LibOnly = 2;
	const long ASUpdateType_None = 3;
	const long ASUpdateType_OnTimer = 4;
	const long ASUpdateType_Module = 5;
	const long ASUpdateType_Leak = 6;
	const long ASUpdateType_Program = 7;
	const long ASUpdateType_AllLib = 8; 
	//优先升级设置,依次为外网模式,外网优先,内网模式,内网优先
	const long ASLibUpdateMode_FromInternet = 0;
	const long ASLibUpdateMode_InternetFirst = 1;
	const long ASLibUpdateMode_FromIntranet = 2;
	const long ASLibUpdateMode_IntranetFirst = 3;
	const long ASLibUpdateMode_Invalid = 10;
	//////////////////////////////////////////////////////////////////////////
	// 发送模块升级通知用到的3个key,表示升级的模块|结果,已经升级的文件,都是utf-8,文件或模块有多个时用分号分割
	const char* const ASUpdateKey_Module = "update_module";
	const char* const ASUpdateKey_Result = "update_result";
	const char* const ASUpdateKey_Result_Detail = "update_result_detail";
	const char* const ASUpdateKey_UpdatedFiles = "update_files";
	const char* const ASUpdateKey_UpdatedModules = "update_modules";
	//升级完是否重新启动进程
	const char* const ASUpdateKey_Reboot = "update_reboot";
	//升级的程序文件模块,库模块,工具模块,补丁库模块
	const char* const ASUpdateKey_Result_Program = "update_result_program";
	const char* const ASUpdateKey_Result_VirusLib = "update_result_viruslib";
	const char* const ASUpdateKey_Result_Leak = "update_result_leak";
	const char* const ASUpdateKey_Result_EpMainVer = "update_result_epmainver";
	const char* const ASUpdateKey_UpdatedModules_Program = "update_modules_program";
	const char* const ASUpdateKey_UpdatedModules_Tools = "update_modules_tools";
	const char* const ASUpdateKey_UpdatedModules_Lib = "update_modules_lib";
	const char* const ASUpdateKey_UpdatedModules_Leak = "update_modules_leak";
	//升级参数,升级的url和目标版本号,是否需要修正下载域名,修正的下载域名地址
	const char* const ASUpdateParam_Url = "url";
	const char* const ASUpdateParam_DestVer = "version";
	const char* const ASUpdateParam_NeedRepairDomain = "repair_domain";
	const char* const ASUpdateParam_RepairDomainAddr = "repair_domain_addr";
	const char* const ASUpdateParam_LocalServerPath = "local_server_path";
	const char* const ASUpdateParam_RollBackMode = "roll_back_mode";

	//const char* const ASUpdateKey_UpdatedModules_Success = "update_modules_success";

	//////////////////////////////////////////////////////////////////////////
	//内部常用的一些模块的id,统一在这里声明
	const char* const AS_MODULEID_360BASE		= "360base";
#ifdef __linux__
	const char* const AS_MODULEID_ENTCLIENT		= "360av_linux_server_base";
#else
	const char* const AS_MODULEID_ENTCLIENT		= "entclient";
#endif
	const char* const AS_MODULEID_UPDCORE		= "client_upd_core";
	const char* const AS_MODULEID_VIRUSLIB		= "engine_360";
	const char* const AS_MODULEID_ENGINE_AVIRA	= "engine_avira";
	const char* const AS_MODULEID_LEAKLIB		= "leaklib";
	const char* const AS_MODULEID_SECURITY_UPDATE = "security_update";	// security_update模块，默认为空，总是认为安装
	
	/////////////////////////////////////////////////////////////////////
	// 模块和appid的兼容类型
	const char* const AS_APPID_COEXIST_TYPE    = "coexist";			//可共存
	const char* const AS_APPID_COMPATIBLE_TYPE = "compatible";		//完全兼容
	const char* const AS_APPID_INCOMPATIBLE_TYPE  = "incompatible";	//不兼容

	//////////////////////////////////////////////////////////////////////////
	//升级相关的一些api
	const char* const CHECK_VIRUS_UPDATE_API = "api/checkvirusupdate.json"; //控制台升级病毒库接口
	const char* const CHECK_LIB_UPDATE_API = "api/checklibupdate.json";
	const char* const CHECK_PROGRAM_UPDATE_API = "api/checkupdate.json";
	const char* const CHECK_LIB_UPDATE_URL_INTERNET = "https://api.b.qianxin.com/api/checklibupdate";


	//////////////////////////////////////////////////////////////////////////
	//asmodule的各种定义    
	//模块状态定义    
	const int AS_MODSTATE_UNKNOWN = -1;				//未知
	const int AS_MODSTATE_UNINSTALL_PENDING = 0;	//卸载需要重启，这种情况不能安装
	const int AS_MODSTATE_INSTALLED = 1;			//已安装
	const int AS_MODSTATE_UNINSTALLED = 2;			//已卸载

	//ASModule的属性，都在模块xml中配置，内部保存时值全用utf8字符串
	const char* const AS_MODULE_ATTR_ID			= "id";
	const char* const AS_MODULE_ATTR_NAME		= "name";
	const char* const AS_MODULE_ATTR_DESC		= "desc";
	const char* const AS_MODULE_ATTR_VERSION	= "version";
	const char* const AS_MODULE_ATTR_OS			= "os";
	const char* const AS_MODULE_ATTR_BIT		= "bit";
	const char* const AS_MODULE_ATTR_EXCLUDEOS	= "exclude_os";
	const char* const AS_MODULE_ATTR_FAT		= "fat";				//fat模块用下载7z解压的方式安装
	const char* const AS_MODULE_ATTR_LIB		= "lib";				//是否病毒库
	const char* const AS_MODULE_ATTR_LEAK       = "leak";               //是否补丁库
	const char* const AS_MODULE_ATTR_CORE		= "core";				//是否关键模块
	const char* const AS_MODULE_ATTR_EXTRA		= "extra";				//是否辅助模块，辅助模块不自动升级
	const char* const AS_MODULE_ATTR_NOTIFY		= "update_notify";		//是否升级成功后自动发送广播
	const char* const AS_MODULE_ATTR_INDIRECT	= "indirect";			//间接模块，模块化不直接管理它的安装卸载，由其他模块控制
	const char* const AS_MODULE_ATTR_RELY		= "depends";			//依赖模块
	const char* const AS_MODULE_ATTR_CONTAINED	= "contained";			//包含于某个模块
	const char* const AS_MODULE_ATTR_EXTEND		= "extend";				//是否扩展模块
	const char* const AS_MODULE_ATTR_EXT3RD     = "ext3rd";             //是否第三方扩展模块
};


#endif /* ASModularize_h */
