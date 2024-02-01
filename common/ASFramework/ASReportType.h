//
//  ASFramework.h
//  ASFramework
//
//  Created by dengfan on 16/12/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASReportType_h
#define ASReportType_h

//上报给控制中心的log类型在这里定义

namespace ASReportTypes
{
	//升级log,用于模块安装卸载上报
	const char* const ASReportType_Update = "update";
	const char* const ASReportType_Install = "install_info";

	const char* const ASReportFilterType_ALL = "*";
};

#endif //ASReportType_h