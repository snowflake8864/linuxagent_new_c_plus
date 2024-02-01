#ifndef UTILS_SYSTEM_UTILS_H_
#define UTILS_SYSTEM_UTILS_H_

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sstream>
#include "utils/file_utils.h"
#include "utils/string_utils.hpp"
#include <string>

namespace system_utils {
std::string GetOsVersion() {
    struct utsname name;
    ::bzero(&name, sizeof(name));

    if (::uname(&name) == -1) {
        return std::string();
    }

    std::string os_ver;
    os_ver.append(name.sysname);
    os_ver.append(" ");

    os_ver.append(name.nodename);
    os_ver.append(" ");

    os_ver.append(name.release);
    os_ver.append(" ");

    os_ver.append(name.version);
    os_ver.append(" ");
    os_ver.append(name.machine);

    return os_ver;
}

bool SuperSystem(const std::string& cmd, const std::string& module_name,
                 std::string& err_str) {
    if (cmd.empty()) {
        return false;
    }

    std::stringstream ss;
    bool is_ok = false;
    do {
        int status = system(cmd.c_str());
        if (status < 0) {
            ss << "do " << module_name << " cmd error: " << strerror(errno);
            break;
        }

        if (WIFEXITED(status)) {
            //取得cmdstring执行结果
            if (WEXITSTATUS(status) == 0) {
                return true;
            } else {
                ss << module_name << " cmd normal termination, exit status = "
                   << WEXITSTATUS(status);
                break;
            }
        } else if (WIFSIGNALED(status)) {
            //如果cmdstring被信号中断，取得信号值
            ss << module_name << " cmd abnormal termination, signal number = "
               << WTERMSIG(status);
            break;

        } else if (WIFSTOPPED(status)) {
            //如果cmdstring被信号暂停执行，取得信号值
            ss << module_name
               << " cmd process stopped, signal number = " << WTERMSIG(status);
            break;

        } else {
            //如果cmdstring被信号暂停执行，取得信号值
            ss << "unknown Error when do " << module_name << " cmd";
            break;
        }
        is_ok = true;
    } while (false);
    err_str = ss.str();
    return is_ok;
}

int AddSyslogConfig(const std::string& conf) {
    const char* configfile = "/etc/rsyslog.d/50-default.conf";
    int fd = -1;
    struct stat st;
    char* buf = NULL;
    ssize_t nread = 0, nwrite = 0;
    std::string dirname;
    std::string tempfile;
    std::string newsyslogconf;

    dirname = file_utils::GetParentDir(configfile);
    tempfile = dirname + "/" + ".tempsyslog.conf";

    fd = ::open(configfile, O_RDWR);
    if (fd == -1) {
        return -1;
    }
    ::fstat(fd, &st);
    buf = new (std::nothrow) char[st.st_size + 1];
    if (buf == NULL) {
        ::close(fd);
        return -1;
    }

    nread = ::read(fd, buf, st.st_size);
    if (nread != st.st_size) {
        ::close(fd);
        delete[] buf;
        return -1;
    }
    ::close(fd);
    buf[st.st_size] = '\0';

    if (::strstr(buf, conf.c_str()) != NULL) {
        delete[] buf;
        return 0;
    }

    newsyslogconf = std::string(buf) + "\n" + conf + "\n";
    delete[] buf;
    fd = ::open(tempfile.c_str(), O_RDWR | O_CREAT | O_TRUNC, st.st_mode);
    if (fd == -1) {
        return -1;
    }

    nwrite = ::write(fd, newsyslogconf.c_str(), newsyslogconf.size());
    if (nwrite != (ssize_t)newsyslogconf.size()) {
        ::close(fd);
        return -1;
    }
    if (::fchown(fd, st.st_uid, st.st_gid) == -1) {
        ::close(fd);
        return -1;
    }
    ::close(fd);

    if (::rename(tempfile.c_str(), configfile) != 0) {
        return -1;
    }

    return 0;
}

int GetRandIntValue() {
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd == -1) return -1;

    unsigned int seed = 0;
    if (read(fd, &seed, sizeof(unsigned int)) == -1) {
        close(fd);
        return -1;
    }

    return rand_r(&seed);
}

std::string GetRandStrValue() {
    return string_utils::ToString(GetRandIntValue());
}

bool SendSig(pid_t pid, int sig) { return (kill(pid, sig) == 0); }

} // namespace

#endif