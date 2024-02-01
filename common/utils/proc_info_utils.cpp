#include "utils/proc_info_utils.h"
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fstream>
#include <sstream>
#include <tr1/memory>
#include "utils/string_utils.hpp"

namespace proc_info_utils {
bool IsCriticalProcess(const uid_t pid) {
    std::string link, pid_string;
    std::stringstream ss;
    ss << pid;
    pid_string = ss.str();

    std::string proc_exe = std::string("/proc/") + pid_string + "/exe";
    link = GetSymLinkTarget(proc_exe);
    // if binary file of process is not existing, then it's kernal process
    if (link.size() > 0) {
        return false;
    } else {
        return true;
    }
}

std::string GetUserName(const uid_t uid) {
    std::string user_name;
    int buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buf_size == -1)   /* Value was indeterminate */
        buf_size = 16384; /* Should be more than enough */
    char *buf = (char *)malloc(buf_size);
    if (buf == NULL) {
        return user_name;
    }
    struct passwd pwd;
    struct passwd *result = NULL;
    int ret = getpwuid_r(uid, &pwd, buf, buf_size, &result);
    if (ret == 0 && result != NULL) {
        // it's a user
        user_name = pwd.pw_name;
    }
    free(buf);
    return user_name;
}

std::string GetUserName(const std::string &status_file) {
    std::ifstream file(status_file.c_str());
    if (!file) {
        return std::string();
    }
    std::string str_line;
    while (std::getline(file, str_line)) {
        if (str_line.empty()) {
            break;
        }

        std::string::size_type idx = str_line.find(':');
        if (str_line.substr(0, idx) == "Uid") {
            std::string uids =
                str_line.substr(idx + 1, str_line.length() - idx - 1);
            string_utils::Trim(uids);
            idx = uids.find('\t');
            file.close();
            return GetUserName(static_cast<uid_t>(
                strtoull(uids.substr(0, idx).c_str(), NULL, 10)));
        }
    }
    file.close();
    return std::string();
}

std::string GetFileContent(const std::string &file_name) {
    std::ifstream file(file_name.c_str());
    if (!file) return std::string();
    std::string str_line;
    std::getline(file, str_line);
    file.close();
    return str_line;
}

std::string GetExecFileName(const uid_t pid) {
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

    return GetExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);
}
std::string GetExecFileName(const std::string &proc_comm,
                            const std::string &proc_exe,
                            const std::string & /*proc_cmdline*/,
                            const std::string &proc_stat) {
    std::string link;
    link = GetSymLinkTarget(proc_exe);
    if (link.size() > 0) {
        std::string file_name;
        std::string::size_type slash_pos;
        slash_pos = link.rfind("/");
        if (slash_pos != std::string::npos) {
            file_name = link.substr(slash_pos + 1);
        } else {
            file_name = link;
        }

        //去掉deleted字段
        std::string find_string = " (deleted)";
        if (file_name.size() > find_string.size()) {
            if (file_name.substr(file_name.size() - find_string.size()) ==
                find_string) {
                file_name =
                    file_name.substr(0, file_name.size() - find_string.size());
            }
        }
        return file_name;
    } else {
        //内核进程直接返回comm内容
        std::string comm = GetFileContent(proc_comm);
        if (!comm.empty()) {
            return comm;
        } else {
            std::vector<std::string> split_stat;
            SplitFile(proc_stat, ' ', '(', ')', split_stat);
            if (split_stat.size() > 2) {
                if (split_stat[1].size() > 2) {
                    return split_stat[1].substr(1, split_stat[1].size() - 2);
                } else {
                    return std::string();
                }
            } else {
                return std::string();
            }
        }
    }
}
std::string GetCmdline(const std::string &proc_cmdline) {
    std::vector<std::string> split_cmd;
    SplitFile(proc_cmdline, 0, split_cmd);
    if (split_cmd.size() == 0) {
        return std::string();
    }
    return CombinCmdArgs(0, split_cmd);
}

std::string GetExecFullFileName(const uid_t pid) {
    std::string pid_string;
    std::string proc_exe;
    std::string proc_comm;
    std::string proc_cmdline;
    std::string proc_name;
    std::string proc_stat;

    std::stringstream ss;
    ss << pid;
    pid_string = ss.str();

    proc_exe = std::string("/proc/") + pid_string + "/exe";
    proc_cmdline = std::string("/proc/") + pid_string + "/cmdline";
    proc_comm = std::string("/proc/") + pid_string + "/comm";
    proc_stat = std::string("/proc/") + pid_string + "/stat";

    proc_name = GetExecFileName(proc_comm, proc_exe, proc_cmdline, proc_stat);

    return GetExecFullFileName(proc_exe, proc_name);
}

std::string GetExecFullFileName(const std::string &proc_exe,
                                const std::string &exec_name) {
    std::string link;
    std::string full_file_name;

    link = GetSymLinkTarget(proc_exe);
    if (link.size() > 0) {
        full_file_name = link;
        std::string::size_type idx;
        idx = full_file_name.rfind(exec_name);
        if (idx != std::string::npos) {
            full_file_name = full_file_name.substr(0, idx + exec_name.size());
        }
    }
    return full_file_name;
}

size_t GetMemorySize(const std::string &status_file) {
    std::ifstream file(status_file.c_str());
    if (!file) {
        return 0;
    }
    std::string str_line;
    while (std::getline(file, str_line)) {
        if (str_line.empty()) {
            break;
        }

        std::string::size_type idx = str_line.find(':');
        if (str_line.substr(0, idx) == "VmHWM") {
            std::string mem_size_string =
                str_line.substr(idx + 1, str_line.length() - idx - 1);
            idx = mem_size_string.find("kB");
            mem_size_string = mem_size_string.substr(0, idx);
            string_utils::Trim(mem_size_string);
            file.close();
            return strtoull(mem_size_string.substr(0, idx).c_str(), NULL, 10);
        }
    }
    file.close();
    return 0;
}

ssize_t GetParentPid(const std::string &proc_stat) {
    std::vector<std::string> split_stat;
    SplitFile(proc_stat, ' ', '(', ')', split_stat);
    if (split_stat.size() >= 4) {
        return atoi(split_stat[3].c_str());
    }
    return -1;
}

// std::string& Trim(std::string& s) {
//     if (s.empty()) {
//         return s;
//     }
//     std::string::size_type begin_pos = s.find_first_not_of(" \t");
//     if (begin_pos != std::string::npos) {
//         s.erase(0, begin_pos);
//     }
//     std::string::size_type end_pos = s.find_last_not_of(" \t\n\r");
//     if (end_pos != std::string::npos) {
//         s.erase(end_pos + 1);
//     }
//     return s;
// }

std::string GetSymLinkTarget(const std::string &path) {
    char target[PATH_MAX + 1] = {0};
    int length = readlink(path.c_str(), target, PATH_MAX);
    if (length == -1) {
        return std::string();
    }
    return std::string(target, length);
}

void SplitFile(const std::string &file_path, char separator,
               std::vector<std::string> &cmd_args) {
    cmd_args.clear();
    std::ifstream file(file_path.c_str());
    if (!file) {
        return;
    }

    std::string str_line;
    std::getline(file, str_line);
    file.close();

    std::string tmp;
    std::string::size_type sub_str_begin = 0, sub_str_end = 0;
    for (std::string::size_type i = 0; i < str_line.size(); ++i) {
        if (str_line[i] == separator) {
            if (sub_str_begin != sub_str_end) {
                tmp =
                    str_line.substr(sub_str_begin, sub_str_end - sub_str_begin);
                cmd_args.push_back(tmp);
                sub_str_begin = sub_str_end + 1;
            } else {
                ++sub_str_begin;
            }
        }
        ++sub_str_end;
    }
    if (sub_str_begin != sub_str_end) {
        cmd_args.push_back(
            str_line.substr(sub_str_begin, sub_str_end - sub_str_begin));
    }
}

void SplitFile(const std::string &file_path, const char separator,
               const char left_ignore_separator,
               const char right_ignore_separator,
               std::vector<std::string> &cmd_args) {
    cmd_args.clear();
    std::ifstream file(file_path.c_str());
    if (!file) {
        return;
    }
    std::string str_line;
    std::getline(file, str_line);
    file.close();
    if (str_line.empty()) {
        return;
    }

    std::string tmp;
    bool in_args_begin = true;
    std::string::size_type sub_str_begin = 0, sub_str_end = 0;
    for (std::string::size_type i = 0; i < str_line.size();) {
        if (str_line[i] == left_ignore_separator && in_args_begin) {
            std::string::size_type right_ignore_separator_pos =
                str_line.rfind(right_ignore_separator);
            if (right_ignore_separator_pos != std::string::npos) {
                sub_str_end = right_ignore_separator_pos;
                i = right_ignore_separator_pos;
                continue;
            }
        } else if (str_line[i] == separator) {
            if (sub_str_begin != sub_str_end) {
                tmp =
                    str_line.substr(sub_str_begin, sub_str_end - sub_str_begin);
                cmd_args.push_back(tmp);
                sub_str_begin = sub_str_end + 1;
                in_args_begin = true;
            } else {
                ++sub_str_begin;
            }
        } else {
            in_args_begin = false;
        }

        ++sub_str_end;
        ++i;
    }
    if (sub_str_begin != sub_str_end) {
        cmd_args.push_back(
            str_line.substr(sub_str_begin, sub_str_end - sub_str_begin));
    }
}

std::string CombinCmdArgs(size_t start_pos,
                          std::vector<std::string> &split_cmd) {
    std::string rs;
    std::string::size_type black_pos;
    for (; start_pos < split_cmd.size(); ++start_pos) {
        black_pos = split_cmd[start_pos].find(' ');
        if (black_pos != std::string::npos) {
            rs += "\"" + split_cmd[start_pos] + "\" ";
        } else {
            rs += split_cmd[start_pos] + " ";
        }
    }
    return string_utils::Trim(rs);
}

std::string GetInstallPath() {
    std::string install_path = "/opt/osecsafe/";
    char szTemp[PATH_MAX] = {0};
    int nRet = readlink("/proc/self/exe", szTemp, PATH_MAX);
    if (nRet > 0 && nRet < PATH_MAX) {
        szTemp[nRet] = '\0';

        char *pLast = strrchr(szTemp, '/');
        if ((pLast != NULL) && (pLast != szTemp)) {
            szTemp[pLast - szTemp] = '\0';
        }
        install_path = szTemp;
    }

    return install_path;
}

std::string GetAppPath() {
    std::string install_path = "/opt/osecsafe/osecentclient";
    char szTemp[PATH_MAX] = {0};
    int nRet = readlink("/proc/self/exe", szTemp, PATH_MAX);
    if (nRet > 0 && nRet < PATH_MAX) {
        install_path = szTemp;
    }
    return install_path;
}

pid_t GetTid() {
#ifdef _GNU_SOURCE
    return syscall(SYS_gettid);
#else
    return gettid();
#endif
};

//检查进程是否存在，调用该函数请确保有权利向相应进程发送信号
bool IsProcExist(int pid) {
    bool exist = true;
    if (kill(pid, 0) == -1) {
        if (errno == ESRCH) {  //只有确认errno为ESRCH时才能确保进程不存在
            exist = false;
        } else {
            printf(
                "failed to check process %d is existing or not,because: %s\n",
                pid, strerror(errno));
        }
    }
    return exist;
}

pid_t GetPid(const std::string &process_name) {
    std::string cmd = "pgrep -f " + process_name;
    FILE *pfp = popen(cmd.c_str(), "r");
    if (pfp == NULL) {
        return -1;
    }
    std::tr1::shared_ptr<FILE> pf_handle(pfp, pclose);
    char buf[16] = {0};
    if (fgets(buf, sizeof(buf), pf_handle.get()) == NULL) {
        return -1;
    }
    std::string pid_str = buf;
    string_utils::TrimRight(pid_str, "\n");
    int pid = -1;
    if (!string_utils::ToInt(pid_str, pid)) {
        return -1;
    }
    return pid;
}
}
