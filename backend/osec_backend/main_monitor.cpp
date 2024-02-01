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
#include "CSimpleMonitor.h"

int main(int argc, char** argv) 
{
    mallopt(M_MMAP_THRESHOLD, 1 * 1024);
        // 创建监控进程
    CSimpleMonitor monitor;
    std::string str_install_path = "/opt/osec";
    std::string str_run_path = str_install_path + "/MagicArmor_0";
    printf("main creater monitor process\n");
    monitor.CreateMonitor(str_run_path, str_install_path);

    CSignalHandler::install_signal_handler();
    sleep(1);

    sigset_t sigset;
    sigemptyset(&sigset);
    signal(SIGPIPE, SIG_IGN);
    sigaddset(&sigset, SIGALRM);
    sigaddset(&sigset, SIGIO);
    sigaddset(&sigset, SIGINT); 
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGWINCH);
    sigaddset(&sigset, SIGABRT);

    sigset_t emptysigset;
    sigemptyset(&emptysigset);

    if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1) {
        LOG_ERROR("sig k() failed,because: %s\n", strerror(errno));
    }

    while (!CSignalHandler::quit()) {
        sigsuspend(&emptysigset);
    }
    LOG_INFO("exit!");
    exit(0);
}
