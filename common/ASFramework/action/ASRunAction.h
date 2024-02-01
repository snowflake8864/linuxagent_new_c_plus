//
//  ASRunAction.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASRunAction_h
#define ASRunAction_h

#include "ASCommonAction.h"
#include <ASFramework/util/ASPcInfo.h>

namespace ASRunAction
{
	//run exe,windows only
	const char* const  AS_RUNACTION_TYPE_EXE = "Exe";
	//run dll,windows only
	const char* const  AS_RUNACTION_TYPE_SIMPLEDLL = "SimpleDll";

	//////////////////////////////////////////////////////////////////////////
	// RunAction keys
	const char* const  AS_RUNACTION_KEY_X64 = "x64";
	const char* const  AS_RUNACTION_KEY_FILE = "File";
	const char* const  AS_RUNACTION_KEY_PARAM = "Param";
	const char* const  AS_RUNACTION_KEY_ENTRY = "Entry";
	const char* const  AS_RUNACTION_KEY_WAITFOREXIT = "WaitForExit";

	// for 3rd module action
	const char* const  AS_RUNACTION_TRY_COUNT = "NTry";
	const char* const  AS_RUNACTION_Ver = "Ver";
	const char* const  AS_RUNACTION_Ver_File = "VFile";
	const char* const  AS_RUNACTION_Disable_Wow64FsRedirection = "DisableWow64FsRedirection";
	const char* const  AS_RUNACTION_THIRD_PARTY = "third_party";
	const char* const  AS_RUNACTION_RUN_MODE = "system_run";

	//////////////////////////////////////////////////////////////////////////
	// RunAction attrs
	const char* const  AS_RUNACTION_ATTR_BASEDIR = "as.action.run.attr.basedir";

};

class CASRunActionExe : public IASCommonAction
{
public:

	virtual const char* GetType() { return ASRunAction::AS_RUNACTION_TYPE_EXE; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* chVer = NULL){m_b3rd = b3rd; m_strVer = chVer;}

	CASRunActionExe(){m_b3rd = false;}

private:

	CASPcInfo m_pcInfo;
	bool m_b3rd;
	string m_strVer;
};

class CASRunActionSimpleDll : public IASCommonAction
{
public:

	virtual const char* GetType() { return ASRunAction::AS_RUNACTION_TYPE_SIMPLEDLL; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* chVer = NULL){m_b3rd = b3rd; m_strVer = chVer;}

	CASRunActionSimpleDll(){m_b3rd = false;}

private:
	CASPcInfo m_pcInfo;
	bool m_b3rd;
	string m_strVer;
};

#endif //ASRunAction_h