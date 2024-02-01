#ifndef ASLog_h
#define ASLog_h

#include "ASFoundation.h"

typedef enum _ASLogLevel
{
	ASLog_Level_Error = 0,
	ASLog_Level_Warning = 1,
	ASLog_Level_Trace = 2,
	ASLog_Level_Debug,
	ASLog_Level_Diagnose
}ASLogLevel;

const char* const g_ASLogLevelString[] =
{
	"error",
	"warning",
	"trace",
	"debug",
	"diagnose"
};

class IASLog : public IASBundle
{
public:

	virtual bool Init() = 0;

	virtual void SetLogFilePath(const char* file_name) = 0;

	virtual void SetLogLevel(ASLogLevel nLevel) = 0;

	virtual void SetLogMaxSize(size_t lFilesize) = 0;

	virtual bool WriteA(ASLogLevel nLevel,const char* fmt, ...) = 0;

	virtual bool WriteW(ASLogLevel nLevel,const wchar_t* fmt, ...) = 0;

	virtual void UnInit() = 0;
};

namespace ASLog
{
	const size_t ASLog_MaxSize = 100 * 1024 * 1024;
	//////////////////////////////////////////////////////////////////////////
	//log的各种属性,通过上面的接口可以设置,也可通过bundle接口读取和写入    
	const char* const ASLog_Attr_LogLevel = "as.log.attr.log_level";		//log级别,int
	const char* const ASLog_Attr_FilePath = "as.log.attr.file_path";		//log文件全路径,utf8 string
	const char* const ASLog_Attr_AutoFlush = "as.log.attr.auto_flush";		//是否auto_flush,int
	const char* const ASLog_Attr_FilterTag = "as.log.attr.filter_tag";		//log的进程内filter_tag,utf8 string
};

#endif  