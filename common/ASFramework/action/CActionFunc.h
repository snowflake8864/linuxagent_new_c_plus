#ifndef __CACTION_FUNC_H__
#define __CACTION_FUNC_H__

#define AS_MSGACTION_KEY_CONTENT			"Content"
#define AS_ACTION_IF_UPDATE				"ifupd"	// if the file updates, then act. or not

class CActionFunc
{
public:
	static int GetPEFileVer(const char* pchFile, long& lHight, long& lLow);
	static bool GetPEFileVer(const char* pchFile, string& strVer);
	static string GetSystemDir(const char* pchParam, bool bCloseRedirect = false);
	static int GetRealPath(string sreDir, string &strPath, bool bPath = true, bool bCloseRedirect = false);
	static bool EntSafeCopyFile(const char* src, const char* dst);
	static bool SafeMoveFile(const char* src, const char* dst, long max_wait_second);
	static bool BInList(const char* file, const char* file_list);
	static bool IsFileInFrameworkPath(string strFileFullPath,string strFrameWorkDir);
};
#endif