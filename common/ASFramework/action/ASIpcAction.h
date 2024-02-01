//
//  ASIpcAction.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASIpcAction_h
#define ASIpcAction_h

#include "ASCommonAction.h"

namespace ASIpcAction
{
	const char* const  AS_ACTION_TYPE_IPC_OLD = "Msg";
	const char* const  AS_ACTION_TYPE_IPC = "Ipc";

	//////////////////////////////////////////////////////////////////////////
	// IpcAction keys
	const char* const AS_IPCACTION_OLDKEY_DST = "Dst";
	const char* const AS_IPCACTION_OLDKEY_CONTENT = "Content";
	const char* const AS_IPCACTION_OLDKEY_DATATYPE = "DataType";
	const char* const AS_IPCACTION_OLDKEY_BROADCAST = "Broadcast";

	// IpcAction internal attrs
	const char* const AS_IPCACTION_ATTR_ENDPOINT_POINTER = "as.action.ipc.attr.endpoint_pointer";
	const char* const AS_IPCACTION_ATTR_OLDENDPOINT_POINTER = "as.action.ipc.attr.oldendpoint_pointer";
	//////////////////////////////////////////////////////////////////////////
};

class CASMsgAction : public IASCommonAction
{
public:

	virtual const char* GetType() { return ASIpcAction::AS_ACTION_TYPE_IPC_OLD; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* chVer = NULL){m_b3rd = b3rd; m_strVer = chVer;}

	CASMsgAction(){m_b3rd = false;}

private:
	bool m_b3rd;
	string m_strVer;
};

class CASIpcAction : public IASCommonAction
{
public:

	virtual const char* GetType() { return ASIpcAction::AS_ACTION_TYPE_IPC; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* chVer = NULL){m_b3rd = b3rd; m_strVer = chVer;}

	CASIpcAction(){m_b3rd = false;}

private:
	bool m_b3rd;
	string m_strVer;
};

#endif //ASIpcAction_h