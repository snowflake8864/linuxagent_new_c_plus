/*
 *  CKoHelper.cpp
 *  2016.11.03
 *  sly
 */

#include "CKoHelper.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common/log/log.h"
#include "utils/system_utils.hpp"

//TODO: DEBUG 变成 ERROR
namespace CKoHelper {


    static bool unloadKMod(const std::string& modName)
    {
        int count = 0;
        bool ok = false;
        std::string cmd = "/sbin/rmmod ";
        cmd.append(modName);

        while((count < 20) && STATMOD(modName)) {
            ok = ExecCmd(cmd.c_str());
            if(ok) { break; }

            count++;
            usleep(500000); //sleep 0.5 seconds
        }

        return ok;
    }

    bool UnLoadMod(const std::string& modName)
    {
        LOG_DEBUG("unload kernel module: %s",
                modName.c_str());
        return unloadKMod(modName);
    }

    bool LoadMod(const std::string& strModName, 
            const std::string& strDir,
            const std::string& strOpt) 
    {

        bool ok = false;
        if (strModName.empty() || strDir.empty()) {
            return ok;
        }

        /*
         *下面的代码要应对两种情况:
         *1.在非专用机上: 内核模块存在，先rmmod一下，再insmod
         *  这样做的目地是用于后续内核模块在系统不重启时进行升级
         *	如果卸载不掉我们仍然返回成功，以便外围使用旧的内核模块
         *	从而保证整个程序的内核相关功能不至于完全不可用
         *2.专用机上不允许我们自己通过程序加载内核模块
         */
        ok = STATMOD(strModName);
        if (ok) {
#ifdef OSECMJBZ
            LOG_INFO("mod: %s already loaded",
                    strModName.c_str());
            return ok;
#else
            LOG_INFO("mod : %s already loaded,"
                    "so we rmmod it firstly",
                    strModName.c_str());
            ok = unloadKMod(strModName);
            if(!ok) {
                LOG_WARN("remove %s failed from kernel,"
                        "so we will use it",
                        strModName.c_str());
                //此处返回成功，以便外围使用旧的内核模块
                return !ok;
            }
#endif
        }

        DIR* pDirs = NULL;
        pDirs = opendir(strDir.c_str());
        ok = (pDirs != NULL);
        if (!ok) {
            LOG_ERROR("failed to open %s: %s", 
                    strDir.c_str(), strerror(errno));
            return ok;
        }
        int nLen = 0;
        struct dirent* pResult = NULL;
        struct dirent* pFile = AllocDirent(pDirs, &nLen);

        while (!readdir_r(pDirs, pFile, &pResult) && pResult) {
            if(!strncmp(pFile->d_name,
                        strModName.c_str(),
                        strModName.size())) 
            {
                std::string fpath = strDir + "/" + pFile->d_name;
                ok = INSMOD(fpath, strOpt);
                if(ok) break;
            }
            memset((void*)pFile, 0, nLen);
        }

        free(pFile);
        closedir(pDirs);

        if (ok) {
            LOG_INFO("mod : %s loaded success", strModName.c_str());
        } else {
            LOG_ERROR("mod : %s loaded failed", strModName.c_str());
        }

        return ok;
    }


    bool Modprobe(const std::string& strModName, 
            const std::string& strOpt) 
    {

        bool ok1 = false;
        bool ok2 = false;
        if (strModName.empty()) {
            return ok1;
        }   

        std::string fpath =  strModName.c_str();
        ok1 = MODPROBE(fpath, strOpt);
        ok2 = MODPROBE2(fpath, strOpt);
        
        if (ok1||ok2) {
            LOG_INFO("mod : %s loaded success", strModName.c_str());
        } else {
            LOG_ERROR("mod : %s loaded failed", strModName.c_str());
        }   
        return ok1||ok2;
    }


    bool Modinfo(const std::string& strModName, 
            const std::string& strOpt) 
    {

        bool ok1 = false, ok2 = false;
        if (strModName.empty()) {
            return ok1;
        }   

        std::string fpath =  strModName.c_str();
        ok1 = MODINFO(fpath, strOpt);
        ok2 = MODINFO2(fpath, strOpt);
        if (ok1||ok2) {
            LOG_INFO("mod : %s haven modeinfo osec_base", strModName.c_str());
        }
        return ok1||ok2;
    }
    bool Depmod(void) 
    {

        bool ok1 = false, ok2 = false;
        ok1 = DEPMOD();
        ok2 = DEPMOD2();
        if (ok1||ok2) {
            LOG_INFO("mod :depmod success");
        }
        return ok1||ok2;
    }

    static bool fileExists(const char *filename) {
        FILE *file = fopen(filename, "r");
        if (file != NULL) {
            fclose(file);
            return true; // 文件存在
        }   
        return false; // 文件不存在
    }


    bool load_osec_base(void)
    {
        bool ok = false;
        struct utsname name;
        ::bzero(&name, sizeof(name));

        if (::uname(&name) == -1) {
            return ok;
        }
        std::string release = "";
        release.append(name.release);

        std::string osec_base_ko_path = "/opt/osec/osec_base.ko-" + release;  

        if (!fileExists(osec_base_ko_path.c_str())) {  
            LOG_INFO("%s is no exists\n", osec_base_ko_path.c_str());
            return ok;
        }

        std::string osec_base_ln_path = "/lib/modules/" + release + "/kernel/drivers/osec_base.ko";  
        if (fileExists(osec_base_ln_path.c_str())) {  
            LOG_INFO("%s is haven exists\n", osec_base_ln_path.c_str());
            ok = true;
            return ok;
        }


        std::string command = "ln -s " + osec_base_ko_path + " " + osec_base_ln_path;  
        int result = system(command.c_str());  
        if (result == 0) {  
            LOG_INFO("%s is success\n", command.c_str());
            ok = true;
        } else {  
            LOG_INFO("%s is false\n", command.c_str());
        }  

        /*
         *下面的代码要应对两种情况:
         *1.在非专用机上: 内核模块存在，先rmmod一下，再insmod
         *  这样做的目地是用于后续内核模块在系统不重启时进行升级
         *	如果卸载不掉我们仍然返回成功，以便外围使用旧的内核模块
         *	从而保证整个程序的内核相关功能不至于完全不可用
         *2.专用机上不允许我们自己通过程序加载内核模块
         */
        std::string strModName = "osec_base";
        if (STATMOD(strModName)) {
            LOG_INFO("mod : %s already loaded,"
                    "so we rmmod it firstly",
                    strModName.c_str());
            if(!unloadKMod(strModName)) {
                LOG_WARN("remove %s failed from kernel,"
                        "so we will use it",
                        strModName.c_str());
            }
        }


        return ok;
    }

    struct dirent* AllocDirent(DIR* pDirs, int* nLen) {
#ifdef PATH_MAX
        int nPathMax = PATH_MAX;
#else
        int nPathMax = pathconf(pDirs, _PC_PATH_MAX);
        if (nPathMax <= 0) nPathMax = 4096;
#endif

        int nDirentLen = offsetof(struct dirent, d_name) + nPathMax + 1;
        if (nLen) *nLen = nDirentLen;

        struct dirent* pFile = (struct dirent*)malloc(nDirentLen);
        if (pFile == NULL) {
            LOG_DEBUG("exit when alloc dirent failed: out of memory");
            exit(1);  // do not change to return false!
        }
        memset((void*)pFile, 0, nDirentLen);

        return pFile;
    }

    bool ExecCmd(const std::string& strCmd) {
        bool bExecResult = false;
        sighandler_t old_handler;

        if (strCmd.empty()) return bExecResult;

        LOG_INFO("try do cmd: %s", strCmd.c_str());

        old_handler = signal(SIGCHLD, SIG_DFL);
        int status = system(strCmd.c_str());
        if(old_handler != SIG_ERR) {
            signal(SIGCHLD,old_handler);
        }

        if (status < 0) LOG_INFO("do cmd error: %s", strerror(errno));

        if (WIFEXITED(status)) {
            //取得cmdstring执行结果
            LOG_INFO("cmd normal termination, exit status = %d",
                    WEXITSTATUS(status));
            bExecResult = WEXITSTATUS(status) == 0 ? true : false;
        } else if (WIFSIGNALED(status)) {
            //如果cmdstring被信号中断，取得信号值
            LOG_INFO("cmd abnormal termination, signal number = %d",
                    WTERMSIG(status));
        } else if (WIFSTOPPED(status)) {
            //如果cmdstring被信号暂停执行，取得信号值
            LOG_INFO("cmd process stopped, signal number = %d", WSTOPSIG(status));
        } else {
            LOG_ERROR("Unknown Error when do cmd: %s", strCmd.c_str());
        }

        return bExecResult;
    }
    ModMgr::ModMgr()
    {
        GetExpectVersionMod();
        GetModList("/opt/osec");
    }
    void ModMgr::GetExpectVersionMod()
    {
        struct utsname name;
        ::bzero(&name, sizeof(name));

        if (::uname(&name) == -1) {
            return;
        }
        std::string release = "";
        release.append(name.release);
        osRelease = release;
        std::string modStr = "osec_base.ko-" + release;  

        size_t pos1 = release.find('.');  
        size_t pos2 = release.find('.', pos1 + 1);  
        std::string majorVersion = release.substr(0, pos2 + 1);  
        majorVersionMod = "osec_base.ko-" + majorVersion;
        std::string modPathStr = "/opt/osec/" + modStr;
        if (fileExists(modPathStr.c_str())) {  
            LOG_INFO("%s is exists\n", modPathStr.c_str());
            expectVersionMod = modStr;
        }
    }
    void ModMgr::GetModList(const std::string& strDir)
    {
        if (!expectVersionMod.empty()) {
            return;
        }

        DIR* pDirs = NULL;
        pDirs = opendir(strDir.c_str());
        if (!pDirs) {
            LOG_ERROR("failed to open %s: %s", 
                    strDir.c_str(), strerror(errno));
            return ;
        }
        int nLen = 0;
        struct dirent* pResult = NULL;
        struct dirent* pFile = AllocDirent(pDirs, &nLen);

        while (!readdir_r(pDirs, pFile, &pResult) && pResult) {
            std::string fpath = strDir + "/" + pFile->d_name;
            if (fpath.find(majorVersionMod) != std::string::npos) {
                modList.push_back(pFile->d_name);  
            }
            memset((void*)pFile, 0, nLen);
        }

        free(pFile);
        closedir(pDirs);
    }
    void ModMgr::buildDepmod(const std::string& modName)
    {
        std::string osec_base_ln_path = "/lib/modules/" + osRelease + "/kernel/drivers/osec_base.ko";  
        //if (fileExists(osec_base_ln_path.c_str())) 
        {  
            std::string cmd = "rm -f "  + osec_base_ln_path;  
            if (system(cmd.c_str()) == 0) {
                LOG_INFO("%s success\n", cmd.c_str());
            }
        }
        //std::string command = "ln -s /opt/osec/" + modName + " " + osec_base_ln_path;  
        std::string command = "cp -f /opt/osec/" + modName + " " + osec_base_ln_path;  
        int result = system(command.c_str());  
        if (result == 0) {  
            LOG_INFO("%s is success\n", command.c_str());
        } else {  
            LOG_INFO("%s is false\n", command.c_str());
        }  
        if (!Modinfo("osec_base","")) {
            Depmod(); 
        }
 
    }
    static void tryUnloadMod() 
    { 
        std::string strModName = "osec_base";
        if (STATMOD(strModName)) {
            LOG_INFO("mod : %s already loaded,"
                    "so we rmmod it firstly",
                    strModName.c_str());
            if(!unloadKMod(strModName)) {
                LOG_WARN("remove %s failed from kernel,"
                        "so we will use it",
                        strModName.c_str());
            }
        }
    }

    bool ModMgr::AutoLoadMod(void)
    {
        bool ok = false;
        if (!expectVersionMod.empty()) {
            buildDepmod(expectVersionMod);
            tryUnloadMod();
            if (Modprobe("osec_base","")) {
                LOG_INFO("modprob %s ok\n", expectVersionMod.c_str());
                currentMod = expectVersionMod;
                ok = true;
            } 
        } else {
            for (std::list<std::string>::iterator it = modList.begin(); it != modList.end(); ++it) {  
                buildDepmod(*it);
                tryUnloadMod();
                if (Modprobe("osec_base","")) {
                    LOG_INFO("modprob %s ok\n", it->c_str());
                    ok = true;
                    currentMod = *it;
                    break;
                } 
            }  
        }
        if (ok)
            ClearUnusedMod("/opt/osec");
        return ok;
    }
    void ModMgr::ClearUnusedMod(const std::string& strDir)
    {
        DIR* pDirs = NULL;
        pDirs = opendir(strDir.c_str());
        if (!pDirs) {
            LOG_ERROR("failed to open %s: %s", 
                    strDir.c_str(), strerror(errno));
            return ;
        }
        int nLen = 0;
        struct dirent* pResult = NULL;
        struct dirent* pFile = AllocDirent(pDirs, &nLen);
        std::string cmd = "rm -f ";  
        std::string modName;
        while (!readdir_r(pDirs, pFile, &pResult) && pResult) {
            std::string fpath = strDir + "/" + pFile->d_name;
            if (fpath.find(currentMod) == std::string::npos) {
                if (fpath.find("osec_base.ko") != std::string::npos) {
                    if (system((cmd + fpath).c_str()) == 0) 
                    {
                        LOG_INFO("%s success\n", (cmd + fpath).c_str());
                    }
                }
            }
            memset((void*)pFile, 0, nLen);
        }

        free(pFile);
        closedir(pDirs);

    }
};
