#include "procInfo.h"
#include <sys/time.h>
#include "common/log/log.h"
#include <cstring>
#include <stdlib.h>
#include <cassert>
#include <errno.h>
#include <fstream>
#include <pwd.h>
#include <dirent.h>
#include <string.h>
#include <sstream>
#include <map>
#include "common/utils/string_utils.hpp"
#include "common/utils/file_utils.h"

std::string& ProcInfo::trim(std::string& s) {
	if (s.empty()) {
		return s;
	}

	s.erase(0, s.find_first_not_of("\t"));
	s.erase(0, s.find_first_not_of(" "));
	s.erase(s.find_last_not_of("\t") + 1);
	s.erase(s.find_last_not_of(" ") + 1);
	return s;
}

void ProcInfo::splitFile(const std::string& file_path, char separator,
		std::vector<std::string>& cmdargs) {
	cmdargs.clear();
	std::ifstream file(file_path.c_str());
	if (!file) {
		return;
	}

	std::string str_line = "";
	while (getline(file, str_line)) {
		if (str_line.empty()) {
			break;
		}
		file.close();

		std::string tmp;
		std::size_t subStrBegin = 0, subStrEnd = 0;
		for (size_t i = 0; i < str_line.size(); ++i) {
			if (str_line[i] == separator) {
				if (subStrBegin != subStrEnd) {
					tmp = str_line.substr(subStrBegin, subStrEnd - subStrBegin);
					cmdargs.push_back(tmp);
					subStrBegin = subStrEnd + 1;
				} else {
					++subStrBegin;
				}
			}
			++subStrEnd;
		}
		if (subStrBegin != subStrEnd) {
			cmdargs.push_back(
					str_line.substr(subStrBegin, subStrEnd - subStrBegin));
		}
	}
	file.close();
}

void ProcInfo::splitFile(const std::string& file_path, char separator,
		char leftIgnoreSeparator, char rightIgnoreSeparator,
		std::vector<std::string>& cmdargs) {
	cmdargs.clear();
	std::ifstream file(file_path.c_str());
	if (!file) {
		return;
	}

	std::string str_line = "";
	while (getline(file, str_line)) {
		if (str_line.empty()) {
			break;
		}
		file.close();

		std::string tmp;
		bool inArgsBegin = true;
		std::size_t subStrBegin = 0, subStrEnd = 0;
		for (size_t i = 0; i < str_line.size();) {
			if (str_line[i] == leftIgnoreSeparator && inArgsBegin) {
				std::size_t rightIgnoreSeparatorPos =
					str_line.rfind(rightIgnoreSeparator);
				if (rightIgnoreSeparatorPos != std::string::npos) {
					subStrEnd = rightIgnoreSeparatorPos;
					i = rightIgnoreSeparatorPos;
					continue;
				}
			} else if (str_line[i] == separator) {
				if (subStrBegin != subStrEnd) {
					tmp = str_line.substr(subStrBegin, subStrEnd - subStrBegin);
					cmdargs.push_back(tmp);
					subStrBegin = subStrEnd + 1;
					inArgsBegin = true;
				} else {
					++subStrBegin;
				}
			} else {
				inArgsBegin = false;
			}

			++subStrEnd;
			++i;
		}
		if (subStrBegin != subStrEnd) {
			cmdargs.push_back(
					str_line.substr(subStrBegin, subStrEnd - subStrBegin));
		}
	}
	file.close();
}

//获取链接指向的目标,如果不是链接文件,返回空
std::string ProcInfo::getSymLinkTarget(const std::string& path) {
	char target[4096] = {0};
	int length = readlink(path.c_str(), target, 4096);
	if (length == -1) {
		return "";
	}
	return std::string(target, length);
}

std::string ProcInfo::getExecFileName(int pid){
	std::string pid_string;
	std::string proc_exe;
	std::string proc_comm;
	std::string proc_cmdline;
	std::string proc_stat;

	std::stringstream ss;
	ss << pid;
	pid_string = ss.str();

	proc_exe = std::string("/proc/") + pid_string + "/exe";
	proc_cmdline = std::string("/proc/") + pid_string + "/cmdline";
	proc_comm = std::string("/proc/") + pid_string + "/comm";
	proc_stat = std::string("/proc/") + pid_string + "/stat";

	return getExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);
}

std::string ProcInfo::getExecFullFileName(const uid_t pid) {
	std::string pid_string;
	std::string proc_exe;
	std::string proc_comm;
	std::string proc_cmdline;
	std::string procName;
	std::string proc_stat;

	std::stringstream ss;
	ss << pid;
	pid_string = ss.str();

	proc_exe = std::string("/proc/") + pid_string + "/exe";
	proc_cmdline = std::string("/proc/") + pid_string + "/cmdline";
	proc_comm = std::string("/proc/") + pid_string + "/comm";
	proc_stat = std::string("/proc/") + pid_string + "/stat";

	procName = getExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);

	return getExecFullFileName(proc_exe, procName);
}

std::string ProcInfo::getExecFullFileName(const std::string& proc_exe,
		const std::string& exec_name) {
	std::string link;
	std::string fullFileName;

	link = getSymLinkTarget(proc_exe);
	if (link.size() > 0) {
		fullFileName = link;
		std::size_t idx;
		idx = fullFileName.rfind(exec_name);
		if (idx != std::string::npos) {
			fullFileName = fullFileName.substr(0, idx + exec_name.size());
		}
	}
	return fullFileName;
}

std::string ProcInfo::getCmdline(const std::string& cmdline,
		const std::string& procName) {
	std::vector<std::string> splitCmd;
	splitFile(cmdline, 0, splitCmd);
	if (splitCmd.size() == 0) {
		return "";
	}
	return combinCmdArgs(0, splitCmd);
	// if (procName.size() == 0) {
	//     return combinCmdArgs(0, splitCmd);
	// }
	// std::size_t idx;
	// idx = splitCmd[0].find(procName);
	// if (idx != std::string::npos) {
	//     if (splitCmd.size() > 1) {
	//         return combinCmdArgs(1, splitCmd);
	//     } else {
	//         return "";
	//     }
	// } else {
	//     return combinCmdArgs(0, splitCmd);
	// }
}

std::string ProcInfo::combinCmdArgs(std::size_t startPos,
		std::vector<std::string>& splitCmd) {
	std::string rs;
	std::size_t blackPos;
	for (; startPos < splitCmd.size(); ++startPos) {
		blackPos = splitCmd[startPos].find(' ');
		if (blackPos != std::string::npos) {
			rs += "\"" + splitCmd[startPos] + "\" ";
		} else {
			rs += splitCmd[startPos] + " ";
		}
	}
	return trim(rs);
}

std::string ProcInfo::getUserName(uid_t uid) {
	std::string username;
	int bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)   /* Value was indeterminate */
		bufsize = 16384; /* Should be more than enough */
	char* buf = (char*)malloc(bufsize);
	if (buf == NULL) {
		//LOG_ERROR("process info get username failed, malloc fail.");
        LOG_ERROR_DEV("ProcInfo getting user name, malloc fail. size:(%d)", bufsize);
		return username;
	}

	struct passwd pwd;
	struct passwd* result = NULL;
	int ret = getpwuid_r(uid, &pwd, buf, bufsize, &result);
	if (ret == 0 && result != NULL) {
		// it's a user
		username = pwd.pw_name;
	}

	free(buf);

	return username;
}

std::size_t ProcInfo::getMemorySize(const std::string& statusFile) {
	std::ifstream file(statusFile.c_str());
	if (!file) {
		//LOG_ERROR("open file %s failed, because:%s", statusFile.c_str(), std::strerror(errno));
        LOG_ERROR_SYS("ProcInfo getting memory size, failed to open the file. file(%s), err:(%s)", statusFile.c_str(), std::strerror(errno));
		return 0;
	}
	std::string str_line("");
	while (getline(file, str_line)) {
		if (str_line.empty()) {
			break;
		}

		std::size_t idx = str_line.find(':');
		if (str_line.substr(0, idx) == "VmHWM") {
			std::string memSizeString =
				str_line.substr(idx + 1, str_line.length() - idx - 1);
			idx = memSizeString.find("kB");
			memSizeString = memSizeString.substr(0, idx);
			trim(memSizeString);
			file.close();
			return strtoull(memSizeString.substr(0, idx).c_str(), NULL, 10);
		}
	}
	file.close();
	return 0;
}

std::string ProcInfo::getUserName(const std::string& statusFile) {
	std::ifstream file(statusFile.c_str());
	if (!file) {
        LOG_ERROR_SYS("ProcInfo getting user name, failed to open the file. file(%s), err:(%s)", statusFile.c_str(), std::strerror(errno));
		//LOG_ERROR("open file %s failed, because:%s", statusFile.c_str(), std::strerror(errno));
		return std::string();
	}
	std::string str_line("");
	while (getline(file, str_line)) {
		if (str_line.empty()) {
			break;
		}

		std::size_t idx = str_line.find(':');
		if (str_line.substr(0, idx) == "Uid") {
			std::string uids =
				str_line.substr(idx + 1, str_line.length() - idx - 1);
			trim(uids);
			idx = uids.find('\t');
			file.close();
			return getUserName(
					(uid_t)strtoull(uids.substr(0, idx).c_str(), NULL, 10));
		}
	}
	file.close();
	return std::string();
}

std::string ProcInfo::getExecFileName(const std::string& proc_comm,
		const std::string& proc_exe,
		const std::string proc_cmdline,
		const std::string proc_stat) {
	std::string link;
	link = getSymLinkTarget(proc_exe);
	if (link.size() > 0) {
		std::string fileName;
		std::size_t slashPos;
		slashPos = link.rfind("/");
		if (slashPos != std::string::npos) {
			fileName = link.substr(slashPos + 1);
		} else {
			fileName = link;
		}

		//去掉deleted字段
		std::string findString = " (deleted)";
		if (fileName.size() > findString.size()) {
			if (fileName.substr(fileName.size() - findString.size()) ==
					findString) {
				fileName =
					fileName.substr(0, fileName.size() - findString.size());
			}
		}
		return fileName;
	} else {
		//内核进程直接返回comm内容
		std::string comm = getFileContent(proc_comm);
		if (comm.size()) {
			return comm;
		} else {
			std::vector<std::string> splitStat;
			splitFile(proc_stat, ' ', '(', ')', splitStat);
			if (splitStat.size() > 2) {
				if (splitStat[1].size() > 2) {
					return splitStat[1].substr(1, splitStat[1].size() - 2);
				} else {
					return "";
				}
			} else {
				return "";
			}
		}
	}
}

std::string ProcInfo::getFileContent(const std::string& fileName) {
	std::ifstream file(fileName.c_str());
	if (!file) {
		//LOG_ERROR("open file %s failed, because:%s", fileName.c_str(), std::strerror(errno));
        LOG_ERROR_SYS("ProcInfo getting file content, failed to open the file. file(%s), err:(%s)", fileName.c_str(), std::strerror(errno));
		return "";
	}

	std::string str_line = "";
	while (getline(file, str_line)) {
		if (str_line.empty()) {
			break;
		}
		file.close();
		return str_line;
	}
	file.close();
	return "";
}

std::size_t ProcInfo::getParentPid(const std::string& proc_stat) {
	std::vector<std::string> splitStat;
	splitFile(proc_stat, ' ', '(', ')', splitStat);
	if (splitStat.size() >= 4) {
		return atoi(splitStat[3].c_str());
	}
    return 0;
}
std::string ProcInfo::getVendor() {
	return "--";
}
std::string ProcInfo::getPackage() {
	return "--";
}

int ProcInfo::getPriority(const std::string& proc_stat) {
	std::vector<std::string> splitStat;
	splitFile(proc_stat, ' ', '(', ')', splitStat);
	if (splitStat.size() >= 4) {
		return atoi(splitStat[17].c_str());
	}
    return 0;
}
int ProcInfo::getThreadCount(const std::string& proc_stat) {
	std::vector<std::string> splitStat;
	splitFile(proc_stat, ' ', '(', ')', splitStat);
	if (splitStat.size() >= 4) {
		return atoi(splitStat[19].c_str());
	}
    return 0;
}

std::string ProcInfo::getLastTime(const std::string& proc_stat) {
	std::vector<std::string> splitStat;
	splitFile(proc_stat, ' ', '(', ')', splitStat);
	int lasttime = 0;
	FILE *fd = NULL;
	char buff[256] = {0};
	char name[64] = {0};
	char realtime[100] = {0};
	unsigned long btime =0;
	fd = std::fopen ("/proc/stat", "r");
	if (fd == NULL) {
		//LOG_ERROR("failed to open the file: /proc/stat failed,because: %s"
		//		, std::strerror(errno));
        LOG_ERROR_SYS("ProcInfo getting last time, failed to open the file. file(%s), err:(%s)", "/proc/stat", std::strerror(errno));
		return "";
	}
	while (fgets(buff,sizeof(buff),fd) != NULL) {
		if (strstr(buff,"btime") != NULL) {
			sscanf(buff ," %s %lu",name,&btime);
			break;
		}
		bzero(buff,sizeof(buff));
	}

	std::fclose(fd);

	if (splitStat.size() >= 4) {
		lasttime = atoi(splitStat[21].c_str());
	}
	int abstime = btime + lasttime/100;
	time_t tick = (time_t)abstime;
	struct tm tm; 
	tm = *localtime(&tick);
	strftime(realtime, sizeof(realtime), "%Y-%m-%d %H:%M:%S", &tm);
	return realtime;
}

bool ProcInfo::getProcAndDepends(const int pid, Audit_PROCESS& proc_info) {
		proc_info.nProcessID = pid;
		std::string proc_exe;
		std::string proc_comm;
		std::string proc_cmdline;
		std::string status_file;
		std::string proc_stat;
		
		char fileName[8] = {0};
		sprintf(fileName, "%d", pid);
		proc_exe = std::string("/proc/") + fileName + "/exe";
		proc_cmdline = std::string("/proc/") + fileName + "/cmdline";
		status_file = std::string("/proc/") + fileName + "/status";
		proc_comm = std::string("/proc/") + fileName + "/comm";
		proc_stat = std::string("/proc/") + fileName + "/stat";
		proc_info.strName =
			getExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);
		if (proc_info.strName.empty()) {
			return false;
		}
		proc_info.strExecutablePath =
			getExecFullFileName(proc_exe, proc_info.strName);
		proc_info.nWorkingSetSize = getMemorySize(status_file);
		proc_info.strUser = getUserName(status_file);
		proc_info.nParentID = getParentPid(proc_stat);
		proc_info.strVendor = getVendor();
		proc_info.strPackage = getPackage();
		proc_info.nPriority = getPriority(proc_stat); 
		proc_info.nThreadCount = getThreadCount(proc_stat);
		proc_info.strStartTime = getLastTime(proc_stat);
		proc_info.nTime = time(NULL);
		proc_info.hash = "";
		get_depend_so(proc_info.nProcessID, proc_info.map_depends);
		return true;
}

bool ProcInfo::getProcFileName(const int pid, Audit_PROCESS& proc_info) {
	proc_info.nProcessID = pid;
	std::string proc_exe;
	std::string proc_comm;
	std::string proc_cmdline;
	std::string status_file;
	std::string proc_stat;
	
	char fileName[8] = {0};
	sprintf(fileName, "%d", pid);
	proc_exe = std::string("/proc/") + fileName + "/exe";
	proc_cmdline = std::string("/proc/") + fileName + "/cmdline";
	status_file = std::string("/proc/") + fileName + "/status";
	proc_comm = std::string("/proc/") + fileName + "/comm";
	proc_stat = std::string("/proc/") + fileName + "/stat";
	proc_info.hash = "";
	proc_info.strName = getExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);
	if (proc_info.strName.empty()) {
		return false;
	}
	proc_info.strExecutablePath =
		getExecFullFileName(proc_exe, proc_info.strName);
	proc_info.nWorkingSetSize = getMemorySize(status_file);
	proc_info.strUser = getUserName(status_file);
	proc_info.nParentID = getParentPid(proc_stat);
	proc_info.strVendor = getVendor();
	proc_info.strPackage = getPackage();
	proc_info.nPriority = getPriority(proc_stat); 
	proc_info.nThreadCount = getThreadCount(proc_stat);
	proc_info.strStartTime = getLastTime(proc_stat);
	proc_info.nTime = time(NULL);
	return true;
}

#include "common/md5sum.h"

void ProcInfo::get_depend_so(const int &pid, std::vector<std::string> &mapSo) {
	//LOG_INFO("get_depend_so pid:%d", pid);
	std::string cmd_str = "cat /proc/" + string_utils::ToString(pid) + "/maps|awk -F ' ' '{print $6}'|grep .so";
	FILE* stream = popen(cmd_str.c_str(), "r");
	if (stream == NULL) {
		LOG_ERROR_SYS("module get popen failed. cmd:(%s)", cmd_str.c_str());
		return;
	} else {
		//LOG_INFO("get_depend_so cmd:%s", cmd_str.c_str());
		char buf[255] = {0};
		while (fgets(buf, sizeof(buf), stream) != NULL) {
			std::string temp = std::string(buf);
			temp = string_utils::TrimRight(temp);
			//LOG_INFO("module get: %s", temp.c_str());
			mapSo.push_back(temp);
			bzero(buf, sizeof(buf));
		}
		pclose(stream);
	}
}

bool ProcInfo::getProcessInfos(std::vector<Audit_PROCESS>& procInfos) {
	DIR* d;
	struct dirent* file = NULL;
	if (!(d = opendir("/proc"))) {
		//LOG_ERROR("failed to open directory:/proc,because: %s\n", strerror(errno));
        LOG_ERROR_SYS("ProcInfo getting process info, failed to open the file. file(%s), err:(%s)", "/proc", std::strerror(errno));
		return false;
	}

	while (true) {
		file = readdir(d);
		if (file == NULL) {
			break;
		}

		std::string fileName(file->d_name);
		if (isdigit(fileName.at(0))) {
			Audit_PROCESS proc_info;
			proc_info.nProcessID = strtoull(fileName.c_str(), NULL, 10);
			std::string proc_exe;
			std::string proc_comm;
			std::string proc_cmdline;
			std::string status_file;
			std::string proc_stat;

			proc_exe = std::string("/proc/") + fileName + "/exe";
			proc_cmdline = std::string("/proc/") + fileName + "/cmdline";
			status_file = std::string("/proc/") + fileName + "/status";
			proc_comm = std::string("/proc/") + fileName + "/comm";
			proc_stat = std::string("/proc/") + fileName + "/stat";
			proc_info.hash = "";
			proc_info.strName =
				getExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);
			if (proc_info.strName.empty())
				continue;
			proc_info.strExecutablePath =
				getExecFullFileName(proc_exe, proc_info.strName);
			//proc_info.iscritical = isCriticalProcess(proc_info.pid) ? 1 : 0;
			//proc_info.cmdline = getCmdline(proc_cmdline, proc_info.procName);
			proc_info.nWorkingSetSize = getMemorySize(status_file);
			proc_info.strUser = getUserName(status_file);
			proc_info.nParentID = getParentPid(proc_stat);
			proc_info.strVendor = getVendor();
			proc_info.strPackage = getPackage();
			proc_info.nPriority = getPriority(proc_stat); 
			proc_info.nThreadCount = getThreadCount(proc_stat);
			proc_info.strStartTime = getLastTime(proc_stat);
			proc_info.nTime = time(NULL);
			proc_info.nParentID = -100;
			if (!proc_info.strExecutablePath.empty()) {
				procInfos.push_back(proc_info);
			}
		}
	}
	closedir(d);
	return true;
}

bool ProcInfo::getProcessInfosModule(std::vector<Audit_PROCESS>& procInfos) {
	DIR* d;
	struct dirent* file = NULL;
	if (!(d = opendir("/proc"))) {
        LOG_ERROR_SYS("ProcInfo getting process info, failed to open the file. file(%s), err:(%s)", "/proc", std::strerror(errno));
		return false;
	}

	while (true) {
		file = readdir(d);
		if (file == NULL) {
			break;
		}

		std::string fileName(file->d_name);
		if (isdigit(fileName.at(0))) {
			Audit_PROCESS proc_info;
			proc_info.nProcessID = strtoull(fileName.c_str(), NULL, 10);
			std::string proc_exe;
			std::string proc_comm;
			std::string proc_cmdline;
			std::string status_file;
			std::string proc_stat;

			proc_exe = std::string("/proc/") + fileName + "/exe";
			proc_cmdline = std::string("/proc/") + fileName + "/cmdline";
			status_file = std::string("/proc/") + fileName + "/status";
			proc_comm = std::string("/proc/") + fileName + "/comm";
			proc_stat = std::string("/proc/") + fileName + "/stat";
			proc_info.hash = "";
			proc_info.strName =
				getExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);
			if (proc_info.strName.empty())
				continue;
			proc_info.strExecutablePath =
				getExecFullFileName(proc_exe, proc_info.strName);
			proc_info.nWorkingSetSize = getMemorySize(status_file);
			proc_info.strUser = getUserName(status_file);
			proc_info.nParentID = getParentPid(proc_stat);
			proc_info.strVendor = getVendor();
			proc_info.strPackage = getPackage();
			proc_info.nPriority = getPriority(proc_stat); 
			proc_info.nThreadCount = getThreadCount(proc_stat);
			proc_info.strStartTime = getLastTime(proc_stat);
			proc_info.nTime = time(NULL);
			get_depend_so(proc_info.nProcessID, proc_info.map_depends);
			proc_info.nParentID = -100;
			if (!proc_info.strExecutablePath.empty()) {
				procInfos.push_back(proc_info);
			}
		}
	}
	closedir(d);
	return true;
}

bool ProcInfo::isCriticalProcess(const uid_t pid) {
	std::string link, fullFileName, pid_string;

	std::stringstream ss;
	ss << pid;
	pid_string = ss.str();

	std::string proc_exe = std::string("/proc/") + pid_string + "/exe";
	link = getSymLinkTarget(proc_exe);
	if (link.size() > 0) {
		return false;
	} else {
		return true;
		// printf("the binary file of process %s is not existing, it's kernal
		// process\n", exe.c_str());
	}
}
