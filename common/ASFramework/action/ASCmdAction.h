//
//  ASCmdAction.h
//  
//

#ifndef ASCmdAction_h
#define ASCmdAction_h

#include "ASCommonAction.h"

namespace ASCmdAction
{
	//run cmd,linux
	const char* const  AS_CMDACTION_TYPE = "Cmd";

	//////////////////////////////////////////////////////////////////////////
	// CmdAction keys
	const char* const  AS_CMDACTION_KEY_CMDLINE = "Cmdline";

};

class CASCmdAction : public IASCommonAction
{
public:

	virtual const char* GetType() { return ASCmdAction::AS_CMDACTION_TYPE; }

	virtual ASCode Execute();

	virtual void Set3rd(bool b3rd = false, const char* chVer = NULL){m_b3rd = b3rd; m_strVer = chVer;}


private:

	bool m_b3rd;
	string m_strVer;
};
#endif