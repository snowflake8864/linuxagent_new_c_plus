//
//  as_policy_type.h
//  asframework
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef as_netflow_type_h
#define as_netflow_type_h

namespace ASNetFlowType
{
	//申请业务类型
	const char* const ASNetFlow_ApplyType_Update		= "update";
	const char* const ASNetFlow_ApplyType_Download_Leak = "download_leak";
	const char* const ASNetFlow_ApplyType_ModInstall = "module_install"; 
	const char* const ASNetFlow_ApplyType_SoftwareDist = "software_dist";

	const char* const ASNetFlow_ApplyType_SoftMgr		= "ruanjianguanjia";

	//下载，上传的服务器类型
	const char* const ASNetFlow_ServerType_Update = "update_server";
	const char* const ASNetFlow_ServerType_Static_Server = "file_server";
	const char* const ASNetFlow_ServerType_Internet      = "internet";

	const char* const ASNetFlow_ServerType_SoftBox_Server  = "softbox";


	//
};

#endif //as_policy_type_h