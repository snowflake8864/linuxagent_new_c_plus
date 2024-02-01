#ifndef aslogimpl_h
#define aslogimpl_h

#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <map>
#include "ASFramework/ASLog.h"
#include "ASFramework/ASBundle.h"
#include "ASFramework/ASBundleImpl.hpp"
#include "qh_thread/mutex.hpp"
#include "timer/timer_interface.hpp"

struct CmpbyValue {
	bool operator()(const std::pair<std::string, time_t>& lhs, const std::pair<std::string, time_t>& rhs)
	{
	   return lhs.second < rhs.second;
	}
};

class CASLogImpl : public IASLog
{
public:
	virtual ASCode	QueryInterface(const char* pszClsid, void** ppInterface) { return ASErr_NOIMPL; }
	virtual long	AddRef() { __sync_fetch_and_add(&m_lRefCount, 1); return m_lRefCount; }
	virtual long	Release() { __sync_fetch_and_sub(&m_lRefCount, 1); if (0 == m_lRefCount) delete this; return m_lRefCount; }

public:
	virtual void clear() { m_attrBundle.clear();}
	virtual void clone(IASBundleBase* pBundleCloneTo) { m_attrBundle.clone(pBundleCloneTo);}
	virtual ASCode putInt(const char* lpKey,int nValue){ return m_attrBundle.putInt(lpKey,nValue);}
	virtual ASCode putAString(const char* lpKey,const char* lpValue) { return m_attrBundle.putAString(lpKey,lpValue);}
	virtual ASCode putWString(const char* lpKey,const wchar_t* lpValue) { return m_attrBundle.putWString(lpKey,lpValue);}
	virtual ASCode putBinary(const char* lpKey,const unsigned char* lpData,int nLen) { return m_attrBundle.putBinary(lpKey,lpData,nLen);}

	virtual ASCode getInt(const char* lpKey,int* pResult) { return m_attrBundle.getInt(lpKey,pResult);}
	virtual ASCode getBinary(const char* lpKey,unsigned char*lpBuffer,int* pBufLen){ return m_attrBundle.getBinary(lpKey,lpBuffer,pBufLen);}
	virtual ASCode getAString(const char* lpKey,OUT char* lpBuffer,INOUT int* pBufLen){ return m_attrBundle.getAString(lpKey,lpBuffer,pBufLen);}
	virtual ASCode getWString(const char* lpKey,OUT wchar_t* lpBuffer,INOUT int* pBufLen){ return m_attrBundle.getWString(lpKey,lpBuffer,pBufLen);}
	virtual ASCode getKeyList(unsigned char* lpBuffer, INOUT int* pBufLen) { return m_attrBundle.getKeyList(lpBuffer, pBufLen); }
	virtual ASCode getValueType(const char* lpszKey, long* lpType) { return m_attrBundle.getValueType(lpszKey, lpType); }

public:

	virtual bool Init() { return Open(); }
	virtual void UnInit() { Close(); }

	virtual void SetLogMaxSize(size_t lFilesize);
	virtual void SetLogLevel(ASLogLevel nLogLevel);
	virtual void SetLogFilePath(const char* lpszFileName);
	virtual void SetBackupFilePath(const char* lpszFileName);
	virtual void SetBackupFileNum(int nBackupNum);
	virtual void SetBackupFileTime(int nBackupTime);
	virtual void SetBackupFileInterval(int nBackupInterval);

	virtual bool WriteA(ASLogLevel nLevel,const char* fmt, ...);
	virtual bool WriteW(ASLogLevel nLevel,const wchar_t* fmt, ...) { return true; }

public:

	CASLogImpl();
	~CASLogImpl();

	void SetMinFreeSpace(size_t size) { return; }
	void SetRotationsize(size_t size) { return; }

	// 文件输出
	bool Open();
	bool Close();

	// 日志文件备份
	bool LogRotate();
	void SetBackUp(ITimer* pTimerMgr);

private:
	bool WriteBuffer(const char * buff, int len);
	bool WriteWithType(ASLogLevel nLevel, const char * fmt, va_list args);
	bool WriteBody(const char* fmt, va_list args);
	int WriteHeader(char * buf);
	int WriteType(ASLogLevel nLevel, char * buf);

private:
	void BackupLogFile(const std::string& new_file);
	void CheckBackupFiles();
	bool IsNeedBackup(std::string& new_file);
	void GetBackupFiles(std::map<std::string, time_t>& backup_files);

private:
	volatile long m_lRefCount;

	ASLogLevel m_lLogLevel;
	CASBundleImpl m_attrBundle;

	int m_nAutoFlush;
	std::string m_strLogTag;
	std::string m_strFilePath;

	size_t m_nMaxLogFileSize;
	size_t m_nLogFileSize;

	int m_nHandle;
	QH_THREAD::CMutex m_mutex_;

	//提供定时备份机制
	ITimer* m_pTimer;
	std::string m_strBackupDir;
	int m_nBackupNum;
	int m_nBackupTime;
	int m_nBackupInterval;
};

#endif
