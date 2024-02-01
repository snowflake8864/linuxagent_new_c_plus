/*
 * CSimpleMonitor.h
 * 2016.6.28
 * sly
 */

#ifndef ENTCLIENT_ENTCLIENT_CSIMPLEMONITOR_H
#define ENTCLIENT_ENTCLIENT_CSIMPLEMONITOR_H

#include <sys/types.h>
#include <unistd.h>
#include <string>

class CSimpleMonitor {
   public:
    CSimpleMonitor() : m_ppid_fd(-1), m_ppid(-1) {}
    ~CSimpleMonitor() {}

   public:
    void CreateMonitor(const std::string& process_path, const std::string& runpath);
    void RunMonitorChild();
    void Restart();
    void Stop();
    std::string StrProcExitStatus(pid_t pid, int status);
    void cleanStuff();

   private:
    int m_ppid_fd;
    pid_t m_ppid;
    std::string m_ppidfile;
    std::string m_pidfile;
    std::string m_process_path;
};

#endif /* ENTCLIENT_ENTCLIENT_CSIMPLEMONITOR_H */
