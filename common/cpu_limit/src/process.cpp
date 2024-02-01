#include "cpu_limit/include/process.h"
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "log/log.h"

Observer::~Observer() {
}

ProcessEx::ProcessEx():m_pProc(NULL) {
    m_pProc = (struct process*)malloc(sizeof(struct process));
}

ProcessEx::~ProcessEx() {
    m_worker.Stop();
    free(m_pProc);
}

int ProcessEx::init(int pid) {
    m_pProc->pid = pid;
    m_pProc->iStartTime = getStartTime(pid);
    m_pProc->dCpuUsage = 0;
    memset(&(m_pProc->tLastSample), 0, sizeof(struct timeval));

    m_pProc->iLastJiffies = -1;
    sprintf(m_pProc->cStatFile, "/proc/%d/stat", pid);

    FILE* fd = fopen(m_pProc->cStatFile, "r");
    if (fd == NULL) {
        LOG_ERROR("open %s for processEx init failed: %s", m_pProc->cStatFile, strerror(errno));
        return 0;
    }

    fclose(fd);

    m_worker.StartUp(this);
    return 1;
}

int ProcessEx::getStartTime(pid_t pid) {
    char file[20] = {};
    char buffer[1024] = {};
    sprintf(file, "/proc/%d/stat", pid);
    FILE* fd = fopen(file, "r");
    if (fd == NULL) {
        LOG_ERROR("open %s for get start time failed: %s", file, strerror(errno));
        return -1;
    }

    if (fgets(buffer, sizeof(buffer), fd) == NULL) {
        LOG_ERROR("fgets for get start time failed: %s", strerror(errno));
        return -1;
    }

    fclose(fd);

    char* ptr = buffer;
    ptr = (char*)memchr(ptr + 1, ')', sizeof(buffer) - (ptr - buffer));
    int sp = 20;
    while(sp--)
        ptr = (char*)memchr(ptr+1,' ', sizeof(buffer) - (ptr - buffer));

    int iTime = atoi(ptr + 1);
    return iTime;
}

int ProcessEx::getJiffies() {
    FILE* fp = fopen(m_pProc->cStatFile, "r");
    if (fp == NULL) {
        LOG_ERROR("open %s for get Jiffies failed: %s", m_pProc->cStatFile, strerror(errno));
        return -1;
    }

    if (fgets(m_pProc->cBuffer, sizeof(m_pProc->cBuffer), fp) == NULL) {
        LOG_ERROR("fgets for get Jiffies failed: %s", strerror(errno));
        return -1;
    }

    fclose(fp);

    char* ptr = m_pProc->cBuffer;
    ptr = (char*)memchr(ptr + 1, ')', sizeof(m_pProc->cBuffer) - (ptr - m_pProc->cBuffer));
    int sp = 12;
    while(sp--)
        ptr = (char*)memchr(ptr + 1,' ', sizeof(m_pProc->cBuffer) - (ptr - m_pProc->cBuffer));

    int utime = atoi(ptr + 1);
    ptr = (char*)memchr(ptr + 1,' ', sizeof(m_pProc->cBuffer) - (ptr - m_pProc->cBuffer));

    int ktime = atoi(ptr + 1);
    return utime + ktime;
}

unsigned long ProcessEx::timeDiff(const struct timeval* t1, const struct timeval* t2) {
    return (t1->tv_sec - t2->tv_sec)*1000000 + (t1->tv_usec - t2->tv_usec);
}

int ProcessEx::calcateProcessCpuUsage() {
    int jiffes = getJiffies();
    if(jiffes < 0)
        return -1;

    struct timeval now;
    gettimeofday(&now, NULL);

    if (m_pProc->iLastJiffies == -1) {
        m_pProc->tLastSample = now;
        m_pProc->iLastJiffies = jiffes;
        m_pProc->dCpuUsage = -1;
        return 0;
    }

    long dt = timeDiff(&now, &(m_pProc->tLastSample));
    double dMaxJiffies = dt*HZ/1000000.0;
    double dSample = (jiffes - m_pProc->iLastJiffies)/dMaxJiffies;
    if (m_pProc->dCpuUsage == -1) {
        m_pProc->dCpuUsage = dSample;
    } else {
        m_pProc->dCpuUsage = (1 - ALFA)*m_pProc->dCpuUsage + ALFA*dSample;
        notifyObserver(m_pProc->dCpuUsage*100);
        usleep(1000*100);
    }

    m_pProc->tLastSample = now;
    m_pProc->iLastJiffies = jiffes;

    return 0;
}

void ProcessEx::OnActivate(Actor* pActor) {
    if(m_worker.IsActive()) {
        while(1) {
            calcateProcessCpuUsage();
            pthread_testcancel();   //线程取消点
        }
    }
}

void ProcessEx::registerObserver(Observer* pObj) {
    if(pObj != NULL)
        m_pObserver = pObj;
}

void ProcessEx::notifyObserver(double dParam) {
    if(m_pObserver != NULL)
        m_pObserver->update(dParam);
}
