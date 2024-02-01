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


#define  PID_BUF_LEN   (20)
#define  RUN_PID_FILE  "/var/log/myosec.pid"

static bool ProcessPopen(const std::string& cmd, std::string& cmd_buf) {
    FILE *fp = NULL;
    fp = popen(cmd.c_str(),"r");
    char buf[1024] = {0};
    if (fp == NULL) {
        return false;
    }

    int ncout = fread(buf,1,1024-1,fp);
    pclose(fp);
    int i;
    for (i = 0; i < ncout - 1; i ++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    cmd_buf = buf;
    return true;
}

int isProcessRunning(int pid) {
    char stat_path[256];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

    FILE *stat_file = fopen(stat_path, "r");
    if (stat_file != NULL) {
        char cmd[64] = {0};
        snprintf(cmd, sizeof(cmd), "cat /proc/%d/cmdline 2>/dev/null", pid);
        std::string cmd_result;
        ProcessPopen(cmd, cmd_result);
        if (strstr(cmd_result.c_str(), "MagicArmor_0")) {
            fclose(stat_file);
            return 1; // Process with the given PID is running
        }
    }   

    return 0; // Process not found
}


static int fileExists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1; // 文件存在
    }   
    return 0; // 文件不存在
}



//服务进程单实例运行
//返回值: 1--正在运行，0--未运行，-1--出错
int server_is_running()
{

    int fd; 
    if (fileExists(RUN_PID_FILE)) {

        // 读取文件内容
        fd = open(RUN_PID_FILE, O_RDONLY);
        if (fd != -1) {
            char buffer[125];
            ssize_t bytesRead;
            if ((bytesRead = read(fd, buffer, sizeof(buffer))) > 0) {

                buffer[bytesRead] = '\0'; // 添加字符串结束符
                char *endptr;
                long num = strtol(buffer, &endptr, 10); // 将字符串转换为数字
                if (endptr != buffer) {
                    if (isProcessRunning(num)) {
                        printf("===server is runing now! errno=%d\n", errno);
                        close(fd);
                        return 1;
                    }

                }
            }
            flock(fd, LOCK_UN);
            close(fd);
            if (remove(RUN_PID_FILE) == 0) {
                printf("Removed %s.", RUN_PID_FILE);
            }

        }

    }

    fd = open(RUN_PID_FILE, O_WRONLY|O_CREAT, 0777);
    if(fd < 0)
    {
        printf("open run pid err(%d)! %s\n", errno, RUN_PID_FILE);
        return -1;
    }

    // 加锁
    // LOCK_SH 建立共享锁定。多个进程可同时对同一个文件作共享锁定。
    // LOCK_EX 建立互斥锁定。一个文件同时只有一个互斥锁定。
    if(flock(fd, LOCK_EX|LOCK_NB) == -1)
    {
        printf("server is runing now! errno=%d\n", errno);
        close(fd);
        return 1;
    }

    // 加锁成功，证明服务没有运行
    // 文件句柄不要关，也不要解锁
    // 进程退出，自动就解锁了
    LOG_INFO("myserver is not running! begin to run..... pid=%ld\n", (long)getpid());

    char pid_buf[PID_BUF_LEN] = {0};
    snprintf(pid_buf, sizeof(pid_buf)-1, "%ld\n", (long)getpid());

    // 把进程pid写入到/var/run/myserver.pid文件
    int ret = write(fd, pid_buf, strlen(pid_buf));
    if (ret) {
        LOG_INFO("ret is %d\n",ret);
    }
    return 0;
}



int main(int argc, char** argv) 
{
    mallopt(M_MMAP_THRESHOLD, 1 * 1024);
#if 1
    	//进程单实例运行检测
    if(0 != server_is_running())
    {
        LOG_INFO("myserver process is running!!!!! Current process will exit !\n");
        return -1;
    }
#endif

    if (Singleton<LabelMgr>::Instance().Init()) {
        LOG_INFO("init  failed\n");
        return -1;
    }

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
