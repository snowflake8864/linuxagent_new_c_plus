//
//  modularize_updater.h
//  modularize
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef modularize_confkey_h
#define modularize_confkey_h

namespace ASModularizeConfKey
{
	//asmodularize.conf里的配置key
	const char* const AS_MODULARIZE_CONFKEY_UPDATESETTING = "update_setting";
	const char* const AS_MODULARIZE_CONFKEY_AUTOUPDATE = "auto_update";
	const char* const AS_MODULARIZE_CONFKEY_AUTOUPDATE_KEY_ENABLE = "enable";
	const char* const AS_MODULARIZE_CONFKEY_AUTOUPDATE_KEY_FIRST_INTERVAL  = "first_interval";
	const char* const AS_MODULARIZE_CONFKEY_AUTOUPDATE_KEY_UPDATE_INTERVAL = "update_interval";
	const char* const AS_MODULARIZE_CONFKEY_RUN_UPDATE_TYPE = "run_update_type";
	
	//升级运行模式类型
	const char* const AS_MODULARIZE_RUN_UPDATE_NORMAL = "normal";
	const char* const AS_MODULARIZE_RUN_UPDATE_NO_COTROL = "no_control";

	//模块化自动升级的默认间隔,分别为首次和后续,单位为分钟
	const char* const AS_MODULARIZE_AUTOUPDATE_DEFAULT_INTERVAL_FIRST = "30";
	const char* const AS_MODULARIZE_AUTOUPDATE_DEFAULT_INTERVAL_FURTHER = "180";

	//asmodularize.dat里记录模块本地状态的key
	const char* const AS_MODULARIZE_MODULEINFO_KEY = "module_info";
	const char* const AS_MODULARIZE_CLIENTINFO_KEY = "client_info";
	const char* const AS_MODULARIZE_INDIRECT_MODULEINFO_KEY = "indirect_module_info";
	const char* const AS_MODULARIZE_MODULEINFO_KEY_VER = "ver";
	const char* const AS_MODULARIZE_CONTROL_KEY_VER = "control_ver";
	const char* const AS_MODULARIZE_MODULEINFO_KEY_STATE = "state";
	const char* const AS_MODULARIZE_CLIENTINFO_KEY_LASTSTART_SYSTIME = "last_start_systime";
};

#endif //modularize_confkey_h

