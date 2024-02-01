#include <malloc.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "common/signal_handle.h"
#include "common/log/log.h"
#include "common/singleton.hpp"
#include "kernel_event_handler.h"
#include "label_mgr.h"
#include "CSimpleMonitor.h"
#include <errno.h>
#include <sys/file.h>
#include "backend/net_agent/BrowseDir_linux.h"
#include "backend/net_agent/dir_info.h"
#include "osec_common/global_message.h"
#include "common/utils/proc_info_utils.h"


std::string getProcParam(const int& strPid) {
    char buff[256] = {0};
    char cmdline[1024] = {0};
    snprintf(buff, sizeof(buff), "/proc/%d/cmdline", strPid);
    FILE *fp = fopen(buff, "r");
    if (fp == NULL) {
        printf("Getting proc info, failed to open the file. file:(%s), err:(%s)"
                , buff, strerror(errno));
        return 0;
    }

    //cmdline
    size_t len = fread(buff, 1, sizeof(buff) - 1, fp);
    size_t i = 0;

    while (i < len) {
        if (buff[i] == '\0')
            cmdline[i] = ' ';
        else
            cmdline[i] = buff[i];
        i++;
    }

    fclose(fp);
    return cmdline;
}

int main(int argc, char** argv) 
{

    int pid = 2298;
    //std::string filename = proc_info_utils::GetExecFileName(pid);
    std::string filename = proc_info_utils::GetExecFullFileName(pid);
    printf("filename:%s\n",filename.c_str());

     printf("xxxxxxxxxxxxx\n");
   // test(pid);
    std::string filepara = getProcParam(pid);
     printf("filepara:%s\n",filepara.c_str());
    /*
    std::string dir = "/home/zs/test";
    std::vector<std::string> vecDirFile;
    vecDirFile = CBrowseDirLinux::GetDirFilenames(dir.c_str(), false);
    std::vector<std::string>::iterator sub_iter;
    for (sub_iter = vecDirFile.begin(); sub_iter != vecDirFile.end(); sub_iter++) {
        
        FILE_INFO file_info;
        DirInfo::get_file_info(*sub_iter,file_info);
        printf("xxxxxxx:%s, %d\n", file_info.dir.c_str(), file_info.type);
    }*/
    return 0;
}
