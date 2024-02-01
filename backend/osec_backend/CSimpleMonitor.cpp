/*
 * CSimpleMonitor.cpp
 * 2016.6.28
 * sly
 */

#include "CSimpleMonitor.h"
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sstream>
#include "common/log/log.h"
#include "CPidFile.h"
#include "common/utils/proc_info_utils.h"

std::string CSimpleMonitor::StrProcExitStatus(pid_t pid, int status) {
    std::stringstream ss;
    ss << "process[" << pid << "] ";
    if (WIFEXITED(status)) {
        //取得cmdstring执行结果
        ss << "normal termination, _exit status " << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        //如果cmdstring被信号中断，取得信号值
        ss << "termination by signal " << WTERMSIG(status);
    } else if (WIFSTOPPED(status)) {
        //如果cmdstring被信号暂停执行，取得信号值
        ss << "stopped by signal " << WSTOPSIG(status);
    } else {
        ss << "termination with unknown status: " << status;
    }

    return ss.str();
}

void CSimpleMonitor::cleanStuff() {
    if (m_ppid_fd != -1) {
        ::close(m_ppid_fd);
    }
}

void CSimpleMonitor::CreateMonitor(const std::string& process_path, const std::string& runpath)  {
    m_process_path = process_path;
    int fe = access(m_process_path.c_str(), F_OK);
    if (fe != 0) {
        LOG_ERROR("there is no program: %s.",process_path.c_str());
        cleanStuff();
        return;
    }

    m_ppidfile = runpath + "/.osec.ppid";
    m_pidfile = runpath + "/.osec.pid";
    m_ppid_fd = CPidFile::write_pid_file(m_ppidfile.c_str());
    if (m_ppid_fd == -1) {
        LOG_ERROR("failed to write pid file %s,because: %s[%d].", m_ppidfile.c_str(), strerror(errno), errno);
        cleanStuff();
        _exit(EXIT_FAILURE);
    }
    
    RunMonitorChild(); 
}

void CSimpleMonitor::RunMonitorChild() {
    while (1) {
        pid_t pid_osec = proc_info_utils::GetPid("MagicArmor_0");
        if (pid_osec < 0) {
            cleanStuff();
            CPidFile::delete_pid_file(m_ppidfile.c_str());
            CPidFile::delete_pid_file(m_pidfile.c_str());
            Restart();
        }
        sleep(5);
    }
}

void CSimpleMonitor::Restart() {
    //if (access(m_process_path.c_str(), F_OK) == 0) 
    {
        FILE* p = popen(m_process_path.c_str(), "r");
        if (p) pclose(p);
    }
}

void CSimpleMonitor::Stop() {
    if (m_ppid != 1 && m_ppid != -1 && m_ppid != 0) {
        LOG_INFO("stop parent process[%ld].", (long)m_ppid);
        CPidFile::delete_pid_file(m_ppidfile.c_str());
        kill(m_ppid, 9);
    }
}
