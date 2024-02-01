//
//  ASProcUtil.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASProcUtil_h
#define ASProcUtil_h

#include <string>
#include <vector>
#include "ASFramework/ASErrCode.h"
class CASProcUtil
{
public:
	
	static int GetCurPid();
	
	static int GetCurTid();

	static bool Is64BitProcess();

	static std::string GetCurProcessName();
	
	static std::string GetCurProcessFullPath();


	static ASCode GetCurProcessCmdline(std::vector<std::string>& cmdLst);

	//创建新的子进程,语义和linux的system函数一致
	static ASCode CreateChildProcess(const char* lpszExecPath,const char* lpszCmdLine,long long* pChildId,int* pErrCode);

	static void CloseProcHandleOrId(long long nHandleOrId);

	static bool IsProcessActive(long long nHandleOrId);

	static bool IsProcessActiveByPid(unsigned long ulPid);

private:

};

#endif //ASPcInfo_h
