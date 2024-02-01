#pragma once

#include "ASCommonAction.h"

namespace ASFileAction
{
	const char* const AS_FILEACTION_KEY_FILE = "File";
	const char* const AS_FILEACTION_KEY_DEST = "Dest";
	const char* const AS_FILEACTION_KEY_SUBTYPE = "SubType";
	const char* const AS_FILEACTION_KEY_Scr = "Src";
	const char* const AS_FILEACTION_KEY_INSTALL_STATE = "state";

//////////////////////////////////////////////////////////////////////////

	const char* const AS_FILEACTION_TYPE_CHECKTRAVEL = "CheckFileTravel";
	const char* const AS_FILEACTION_SUBTYPE_MOVEDTOMODULE = "MovedToModule";
	const char* const AS_FILEACTION_TYPE_COPYFILE = "CopyFile";
	const char* const AS_FILEACTION_TYPE_MOVEFILE = "MoveFile";

	const char* const  AS_RUNACTION_ATTR_BASEDIR = "as.action.run.attr.basedir";
}

class CASFileActionTravel : public IASCommonAction
{
public:
	CASFileActionTravel(){ m_b3rd = false; }

	virtual const char* GetType() { return ASFileAction::AS_FILEACTION_TYPE_CHECKTRAVEL; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* lpVer = NULL){m_b3rd = b3rd; m_strVer = lpVer;}

protected:

	bool _DeleteFile(const char* lpszFile);

public:
	bool m_b3rd;
	std::string m_strVer;
};


class CASCopyFileAction : public IASCommonAction
{
public:
	CASCopyFileAction(){ m_b3rd = false; }

	virtual const char* GetType() { return ASFileAction::AS_FILEACTION_TYPE_COPYFILE; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* lpVer = NULL){m_b3rd = b3rd; m_strVer = lpVer;}

public:
	bool m_b3rd;
	std::string m_strVer;
};

class CASMoveFileAction : public IASCommonAction
{
public:
	CASMoveFileAction(){ m_b3rd = false; }

	virtual const char* GetType() { return ASFileAction::AS_FILEACTION_TYPE_MOVEFILE; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* lpVer = NULL){m_b3rd = b3rd; m_strVer = lpVer;}

public:
	bool m_b3rd;
	std::string m_strVer;
};