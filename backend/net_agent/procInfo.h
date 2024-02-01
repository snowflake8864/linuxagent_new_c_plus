#ifndef GETPROCINFO_H
#define GETPROCINFO_H

#include <string>
#include <unistd.h>
#include <vector>
#include "osec_common/global_message.h"


class ProcInfo {
   public:
    static std::string getExecFullFileName(const uid_t pid);
    static std::string getExecFileName(int pid);
    static std::string getUserName(const std::string& statusFile);
    static std::string getExecFullFileName(const std::string& proc_exe,
                                           const std::string& exec_name);
    static bool getProcessInfos(std::vector<Audit_PROCESS>& procInfos);
    static bool getProcAndDepends(const int pid, Audit_PROCESS& proc_info);
    static bool  getProcessInfosModule(std::vector<Audit_PROCESS>& procInfos);
    static bool getProcFileName(const int pid, Audit_PROCESS& proc_info);

   private:
    static  void get_depend_so(const int &pid, std::vector<std::string> &mapSo);
    static bool isCriticalProcess(const uid_t pid);
    static std::string getVendor();
    static std::string getPackage();
    static int getPriority(const std::string& proc_stat); 
    static int getThreadCount(const std::string& proc_stat);
    static std::string getLastTime(const std::string& proc_stat);
    static std::string getUserName(uid_t uid);
    static std::string getFileContent(const std::string& fileName);
    static std::string getExecFileName(const std::string& proc_comm,
                                       const std::string& proc_exe,
                                       const std::string proc_cmdline,
                                       const std::string proc_stat);
    static std::string getCmdline(const std::string& cmdline,
                                  const std::string& procName);
    static std::size_t getMemorySize(const std::string& statusFile);
    static std::size_t getParentPid(const std::string& proc_stat);
    static std::string& trim(std::string& s);
    static std::string getSymLinkTarget(const std::string& path);
    static void splitFile(const std::string& file_path, char separator,
                          std::vector<std::string>& cmdargs);
    static void splitFile(const std::string& file_path, char separator,
                          char leftIgnoreSeparator, char rightIgnoreSeparator,
                          std::vector<std::string>& cmdargs);
    static std::string combinCmdArgs(std::size_t startPos,
                                     std::vector<std::string>& splitCmd);
};

#endif  // GETPROCINFO_H
