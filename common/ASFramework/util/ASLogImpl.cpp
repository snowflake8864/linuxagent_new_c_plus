#include "stdafx.h"
#include "ASLogImpl.h"
using namespace ASLog;
using namespace ASBundleHelper;
#include "CStrCvt.h"

#ifdef __linux__
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <algorithm>
#include <vector>
#include "utils/file_utils.h"
#include "utils/proc_info_utils.h"
#include "utils/string_utils.hpp"
#include "utils/time_utils.hpp"
#include "minizip/ckl_zip.h"
#endif

#define HEADER_BUFFER_SIZE	1024

template< typename CharT, typename TraitsT >
inline std::basic_ostream< CharT, TraitsT >& operator<< (
	std::basic_ostream< CharT, TraitsT >& strm, ASLogLevel lvl)
{
	if (static_cast<std::size_t>(lvl) < (sizeof(g_ASLogLevelString) / sizeof(g_ASLogLevelString[0])))
		strm << g_ASLogLevelString[lvl];
	else
		strm << static_cast<int>(lvl);
	return strm;
}

CASLogImpl::CASLogImpl()
{
	m_lRefCount = 0;
	m_nAutoFlush = true;
	m_lLogLevel  = ASLog_Level_Trace;
	m_nMaxLogFileSize = ASLog::ASLog_MaxSize;
	m_nLogFileSize = 0;
	m_nHandle = -1;
	m_pTimer = NULL;
	m_nBackupNum = 7;
	m_nBackupTime = 0;
	m_nBackupInterval = 60;
}

CASLogImpl::~CASLogImpl() {
	if (m_pTimer != NULL) {
		m_pTimer->UnRegisterEvent("timed rotate log file");
		m_pTimer->Release();
	}

	Close();
}

void CASLogImpl::SetLogFilePath(const char* lpszFileName)
{
	assert(lpszFileName && strlen(lpszFileName) > 0);
	if(!(lpszFileName && strlen(lpszFileName) > 0))	return;
	m_strFilePath = lpszFileName;
}

void CASLogImpl::SetLogLevel(ASLogLevel nLogLevel)
{
	assert(nLogLevel >= ASLog_Level_Error && nLogLevel <=ASLog_Level_Diagnose);
	if(!(nLogLevel >= ASLog_Level_Error && nLogLevel <=ASLog_Level_Diagnose))
		return;

	m_lLogLevel = nLogLevel;
}

void CASLogImpl::SetLogMaxSize(size_t lFilesize)
{
	m_nMaxLogFileSize = lFilesize > ASLog_MaxSize ? ASLog_MaxSize : lFilesize;
}

void CASLogImpl::SetBackupFilePath(const char* lpszFileName)
{
	assert(lpszFileName && strlen(lpszFileName) > 0);
	if(!(lpszFileName && strlen(lpszFileName) > 0))	return;
	m_strBackupDir = lpszFileName;
}

void CASLogImpl::SetBackupFileNum(int nBackupNum)
{
	m_nBackupNum = nBackupNum < 0 ? 7 : nBackupNum;
}

void CASLogImpl::SetBackupFileTime(int nBackupTime)
{
	m_nBackupTime = (nBackupTime >= 24 || nBackupTime < 0) ? 0 : nBackupTime;
}

void CASLogImpl::SetBackupFileInterval(int nBackupInterval)
{
	nBackupInterval = (nBackupInterval >= 24 * 60 * 60  || nBackupInterval < 0) ? 60 : nBackupInterval;
}

bool CASLogImpl::LogRotate() {
	std::string new_file;
	if (IsNeedBackup(new_file)) {
		BackupLogFile(new_file);
		CheckBackupFiles();
	}
	return true;
}

bool CASLogImpl::Open() {
	if(m_nHandle != -1) {
		printf("the log file[%s] has been opened before.\n", m_strFilePath.c_str());
		return true;
	}
	if (!file_utils::IsExist(m_strFilePath)) {
		file_utils::MakeDirs(file_utils::GetParentDir(m_strFilePath), 0755);
	}

	m_nHandle = ::open(m_strFilePath.c_str(), O_RDWR|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (m_nHandle == -1) {
		printf("open log file[%s] failed, because: %s.\n", m_strFilePath.c_str(), strerror(errno));
		return false;
	}
	struct stat statbuff;
	if(stat(m_strFilePath.c_str(), &statbuff) < 0) {
		printf("get log file[%s] stat failed, because: %s.\n", m_strFilePath.c_str(), strerror(errno));
		return false;
	} else {
		m_nLogFileSize = statbuff.st_size;
	}
	return true;
}

bool CASLogImpl::WriteBuffer(const char * buff, int len) {
	if(buff == NULL) return false;
	if (m_nLogFileSize + len > m_nMaxLogFileSize) {
		::lseek(m_nHandle, -1 * 1024 * 1024, SEEK_END);
		char *filebuff = new (std::nothrow) char[1 * 1024 * 1024 + 1];
		memset(filebuff, 0, 1 * 1024 * 1024 + 1);
		int readsize = ::read(m_nHandle, filebuff, 1 * 1024 * 1024);
		if (readsize < 0) {
			::lseek(m_nHandle, 0, SEEK_END);
			printf("lograte read data failed, because: [%s].", strerror(errno));
			return false;
		}
		Close();
		if (m_nHandle == -1) {
			m_nHandle = ::open(m_strFilePath.c_str(), O_WRONLY|O_APPEND|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			Close();
		}
		Open();
		int writesize = ::write(m_nHandle, filebuff, readsize);
		if (filebuff != NULL) delete [] filebuff;
		if (writesize != readsize) {
			printf("lograte write log file[%s] failed.", m_strFilePath.c_str());
			return false;
		}
		m_nLogFileSize += writesize;
	}
	int size = ::write(m_nHandle, buff, len);
	if(size != len) {
		printf("write log file[%s] failed, buffer[%s].", m_strFilePath.c_str(), std::string(buff, len).c_str());
		return false;
	}
	m_nLogFileSize += size;

	return true;
}

bool CASLogImpl::Close() {
	if(m_nHandle != -1)
		::close(m_nHandle);
	m_nHandle = -1;
	m_nLogFileSize = 0;
	return true;
}

int CASLogImpl::WriteType(ASLogLevel nLevel, char * buf) {
	const char * s = NULL;
	switch(nLevel) {
		case ASLog_Level_Trace:
			s = "INFO |";
			break;
		case ASLog_Level_Debug:
			s = "DEBUG|";
			break;
		case ASLog_Level_Error:
			s = "ERROR|";
			break;
		case ASLog_Level_Warning:
			s = "WARN |";
			break;
		default:
			buf[0] = ' ';
			return 1;
	}

	int len = strlen(s);
	strncpy(buf, s, len);
	buf[len] = 0;
	return len;
}

bool CASLogImpl::WriteBody(const char* fmt, va_list args) {
	char* buf = NULL;
	if (vasprintf(&buf, fmt, args) == -1) {
		return false;
	}
	size_t len = strlen(buf);
	bool b_ret = WriteBuffer(buf, len);
	if (len > 0 && buf[len - 1] != '\n') {
		b_ret = b_ret && WriteBuffer("\n", 1);
	}

	free(buf);
	return b_ret;
}

bool CASLogImpl::WriteWithType(ASLogLevel nLevel, const char* fmt, va_list args) {
	if (m_nHandle == -1) return false;
	char * buf = (char *) malloc(HEADER_BUFFER_SIZE);
	if (NULL == buf) {
		printf("malloc [%d] failed.", HEADER_BUFFER_SIZE);
		return false;
	}
	memset(buf, 0, HEADER_BUFFER_SIZE);

	int head_len = WriteHeader(buf);
	WriteType(nLevel, buf + head_len);
	bool b_rtn = WriteBuffer(buf, strlen(buf));
	if (b_rtn) {
		b_rtn = WriteBody(fmt, args);
	}

	if (NULL != buf) {
		free(buf);
	}
	return b_rtn;
}

bool CASLogImpl::WriteA(ASLogLevel nLevel,const char * fmt, ...) {
	if ((int)nLevel > (int)m_lLogLevel || fmt == NULL) {
		return false;
	}

	QH_THREAD::CMutexAutoLocker _locker(&m_mutex_);
	va_list args;
	va_start(args, fmt);

	bool b_rtn = WriteWithType(nLevel, fmt, args);

	va_end(args);

	return b_rtn;
}

int CASLogImpl::WriteHeader(char * buf) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm now_tm;
	char time_str[100];
	memset(time_str, 0, 100);
	strftime(time_str, 100, "%Y-%m-%d %H:%M:%S",
				localtime_r((const time_t *)&tv.tv_sec, &now_tm));

	char header_str[200];
	memset(header_str, 0, 200);
	snprintf(header_str, 200, "%s.%.06ld|", time_str, (long)tv.tv_usec);

	char spid[32];
	memset(spid, 0, 32);
	snprintf(spid, 32, "%-5d|", getpid());
	strncat(header_str, spid, 32);

	char stid[32];
	memset(stid, 0, 32);
	snprintf(stid, 32, "%-5d|", proc_info_utils::GetTid());
	strncat(header_str, stid, 32);

	int head_len = strlen(header_str);
	memcpy(buf, header_str, head_len);
	return head_len;
}

void CASLogImpl::SetBackUp(ITimer* pTimerMgr) {
	if (pTimerMgr == NULL) {
		return;
	}

	if (m_strBackupDir.empty() || m_strFilePath.empty()) {
		printf("logrotate, backup file dir is empty!\n");
		return;
	}

	m_pTimer = pTimerMgr;
	m_pTimer->AddRef();

	TimerHandlerConf timedscan_conf;
	timedscan_conf.cycle_time = m_nBackupInterval;
	timedscan_conf.repeat_count = -1;
	timedscan_conf.handler = std::tr1::bind(&CASLogImpl::LogRotate, this);
	pTimerMgr->RegisterEvent(timedscan_conf, "timed rotate log file");

	return;
}

void CASLogImpl::BackupLogFile(const std::string& new_file) {
	QH_THREAD::CMutexAutoLocker _locker(&m_mutex_);
	Close();
	const char * path = m_strFilePath.c_str();
	if (-1 == zip_files(new_file.c_str(), &path, 1, "")) {
		printf("backup file[%s] failed.\n", new_file.c_str());
		return;
	} else {
		printf("backup file[%s] success.\n", new_file.c_str());
		chmod(new_file.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	}
	if (m_nHandle == -1) {
		m_nHandle = open(path, O_WRONLY | O_APPEND | O_TRUNC);
		Close();
	}
	Open();
}

bool CASLogImpl::IsNeedBackup(std::string& new_file) {
	time_t now;
	time(&now);
	struct tm now_tm;
	localtime_r(&now, &now_tm);
	if (now_tm.tm_hour != m_nBackupTime) {
		return false;
	}

	std::string last_time = time_utils::FormatTimeStr(now - 4000, "%Y-%m-%d");
	new_file = m_strBackupDir + "/" + m_strFilePath + "-" + last_time + ".zip";
	return file_utils::IsExist(new_file.c_str()) ? false : true;
}

void CASLogImpl::GetBackupFiles(std::map<std::string, time_t>& backup_files) {
	if (m_strBackupDir.empty()) {
		printf("logrotate, backup dir is empty!\n");
		return;
	}

	// 打开目录
	DIR *dirs;
	if (!(dirs = opendir(m_strBackupDir.c_str())))
		return;

	// 遍历目录中的每一个文件和目录
	struct dirent* result = NULL;

	while ((result = readdir(dirs)) != NULL) {
		do {
			// 跳过非备份文件
			if (strncmp(result->d_name, m_strFilePath.c_str(), m_strFilePath.size()) != 0) {
				break;
			}
			// 获取全路径
			std::string full_path = m_strBackupDir + "/" + result->d_name;
			// 获取文件属性
			struct stat sb, lsb;
			if (lstat(full_path.c_str(), &lsb) != 0 || stat(full_path.c_str(), &sb) != 0) {
				break;
			}
			// 如果实体文件是 一个文件 但不是普通文件 直接跳过
			if (S_ISDIR(sb.st_mode) || ((sb.st_mode & S_IFMT) != S_IFREG) || S_ISLNK(lsb.st_mode)) {
				break;
			}
			backup_files.insert(std::make_pair(full_path, sb.st_mtime));
		} while(0);

	}
	closedir(dirs);
}

void CASLogImpl::CheckBackupFiles() {
	std::map<std::string, time_t> backup_files;
	GetBackupFiles(backup_files);
	if ((int)backup_files.size() < m_nBackupNum) {
		return;
	}
	std::vector<std::pair<std::string, time_t> > backup_files_v(backup_files.begin(), backup_files.end());
	std::sort(backup_files_v.begin(), backup_files_v.end(), CmpbyValue());
	std::vector<std::pair<std::string, time_t> >::iterator it = backup_files_v.begin();
	it = backup_files_v.begin();
	int num = backup_files_v.size() - m_nBackupNum;
	for (int i = 0; i < num && it != backup_files_v.end(); ++it, ++i) {
		printf("logrotate : remove old backup file %s.\n", it->first.c_str());
		remove(it->first.c_str());
	}
}
