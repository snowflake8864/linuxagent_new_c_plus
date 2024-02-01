#ifndef UTILS_PROC_INFO_UTILS_H_
#define UTILS_PROC_INFO_UTILS_H_

#include <linux/limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <vector>

namespace proc_info_utils {

bool IsCriticalProcess(const uid_t pid);
std::string GetUserName(const uid_t uid);
std::string GetUserName(const std::string& status_file);
std::string GetFileContent(const std::string& file_name);
std::string GetExecFileName(const uid_t pid);
std::string GetExecFileName(const std::string& proc_comm,
                            const std::string& proc_exe,
                            const std::string& proc_cmdline,
                            const std::string& proc_stat);
std::string GetCmdline(const std::string& proc_cmdline);
std::string GetExecFullFileName(const uid_t pid);
std::string GetExecFullFileName(const std::string& proc_exe,
                                const std::string& exec_name);
size_t GetMemorySize(const std::string& status_file);
ssize_t GetParentPid(const std::string& proc_stat);
std::string GetSymLinkTarget(const std::string& path);
void SplitFile(const std::string& file_path, char separator,
               std::vector<std::string>& cmdargs);
// read first line from file and split by separator but ignore separator between
// first left_ignore_separator and last right_ignore_separator
void SplitFile(const std::string& file_path, const char separator,
               const char left_ignore_separator,
               const char right_ignore_separator,
               std::vector<std::string>& cmd_args);
std::string CombinCmdArgs(size_t start_pos,
                          std::vector<std::string>& split_cmd);
std::string GetInstallPath();
std::string GetAppPath();
pid_t GetTid();
bool IsProcExist(int pid);
pid_t GetPid(const std::string& process_name);
}

#endif  /* UTILS_PROC_INFO_UTILS_H_ */
