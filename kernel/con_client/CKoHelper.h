/*
 *  CKoHelper.h
 *  2016.11.03
 *  sly
 */

#ifndef _CKOHELPER_H_
#define _CKOHELPER_H_

// #include "UserUtils.h"
#include <dirent.h>
#include <string.h>
#include <string>
#include <list>


#define STATMOD(name)                                                       \
    (ExecCmd(std::string("/sbin/lsmod 2>/dev/null | grep ") + std::string(name) + \
             " 1>/dev/null 2>&1"))
#define INSMOD(path, opt)                                       \
    (ExecCmd(std::string("/sbin/insmod ") + std::string(path) + " " + \
             std::string(opt) + " 1>/dev/null 2>&1"))
#define MODINFO(path, opt)                                       \
    (ExecCmd(std::string("/usr/sbin/modinfo ") + std::string(path) + " " + \
              " 1>/dev/null 2>&1"))
#define MODINFO2(path, opt)                                       \
    (ExecCmd(std::string("/sbin/modinfo ") + std::string(path) + " " + \
              " 1>/dev/null 2>&1"))

#define DEPMOD()                                       \
    (ExecCmd(std::string("/usr/sbin/depmod") + \
              " 1>/dev/null 2>&1"))
#define DEPMOD2()                                       \
    (ExecCmd(std::string("/sbin/depmod") + \
              " 1>/dev/null 2>&1"))

#define MODPROBE(path, opt)                                       \
    (ExecCmd(std::string("/usr/sbin/modprobe ") + std::string(path) + " " + \
              " 1>/dev/null 2>&1"))
#define MODPROBE2(path, opt)                                       \
    (ExecCmd(std::string("/sbin/modprobe ") + std::string(path) + " " + \
              " 1>/dev/null 2>&1"))

namespace CKoHelper {
bool LoadMod(const std::string& StrModName, const std::string& strDir,
             const std::string& strOpt);
bool UnLoadMod(const std::string& modName);
bool Modprobe(const std::string& StrModName,
             const std::string& strOpt);
bool Modinfo(const std::string& StrModName,
             const std::string& strOpt);
bool ExecCmd(const std::string& strCmd);
struct dirent* AllocDirent(DIR* pDirs, int* nLen);
bool load_osec_base(void);
bool Depmod(void); 

class ModMgr {
    public:
        bool AutoLoadMod(void); 
        ModMgr(void);
    private:
        std::list<std::string> modList;
        std::string expectVersionMod;
        std::string currentMod;
        std::string majorVersionMod;
        std::string osRelease;
        void buildDepmod(const std::string& modName);
        void GetExpectVersionMod();
        void GetModList(const std::string& path);
        void ClearUnusedMod(const std::string& strDir);
};

};
#endif
