#include "cpu_limit/include/cpu_limit.h"
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/vfs.h>
#include <errno.h>
#include <string.h>
#include "log/log.h"

CPULimit::CPULimit()
    : m_iSpeed(100), m_dCPU(-0.1), m_uCPUNum(0), m_pProc(NULL), m_cpunum(1) {}

CPULimit::~CPULimit() { uninit(); }

void CPULimit::init() {
    m_pProc = NULL;
    m_dCPU = 0;
    m_uCPUNum = 1;
    start(25);
}

void CPULimit::uninit() {
    if(m_pProc != NULL)
        delete m_pProc;
    m_pProc = NULL;
}

int CPULimit::start(unsigned int iSpeed) {
    if (0 == setSpeedType(iSpeed)) {
        LOG_ERROR("set speed type failed");
        return 0;
    }

    return 1;
}

int CPULimit::stop() {
    return 1;
}

int CPULimit::monitorCPUNum() {
    cpu_set_t cpu_set;
    pthread_t tid = pthread_self();

    /*
    CPU_ZERO(&cpu_set);
    if(pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpu_set) != 0)
    {
        LOG_ERROR("CPULimit:: monitorCPUNum has error! getaffinity");
    }

    if(m_uCPUNum == CPU_COUNT(&cpu_set))
        return 1;
    */

    CPU_ZERO(&cpu_set);
    for(unsigned int i = 0; i < m_uCPUNum; i++)
        CPU_SET(i, &cpu_set);

    if (pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpu_set) != 0) {
        LOG_ERROR("monitor CPU num failed, set affinity");
    }

    return 1;
}

unsigned int CPULimit::getBindCPUNum() {
    return m_uCPUNum;
}

int CPULimit::monitor() {
    // 1、获取当前进程CPU利用率
    if (m_pProc == NULL) {
        //printf("cpu core is greater than 2.\n");
        return 0;
    }

    double cur_speed = m_dCPU/m_cpunum;
    if ((double)m_iSpeed <= cur_speed) {
        LOG_DEBUG(">>>>>>>>>>>>>>>>>> supper speed >>>>>>>>>>>>>>>>>>>>>> \nlimit speed %lf, curent speed %lf", (double) m_iSpeed, (double) cur_speed);
        usleep(1000*100);
    }

    return 1;
}

int CPULimit::getCPUNum() {
    int iNumCpu = -1;
#ifdef _SC_NPROCESSORS_ONLN
    iNumCpu = sysconf(_SC_NPROCESSORS_ONLN);
#elif defined __APPLE__
    int mib[2] = {CTL_HW, HW_NCPU};
    size_t len = sizeof(iNumCpu);
    sysctl(mib, 2, &iNumCpu, &len, NULL, 0);
#endif
    return iNumCpu;
}

// 判断是否存在proc目录
int CPULimit::checkProc() {
    struct statfs mnt;
    if (statfs("/proc", &mnt) < 0) {
        LOG_ERROR("system no /proc directory");
        return 0;
    }

    if (mnt.f_type != 0x9fa0) {
        return 0;
    }

    return 1;
}

// 25 50 100
int CPULimit::setSpeedType(unsigned int iSpeed) {
    LOG_INFO("go into set speed type, %d",iSpeed);
    // 设置需要CPU核心数量
    int iNeedNumberOfProcessors = 0;

    // 设置掩码，不选择任何CPU核心
    cpu_set_t mask;

    // 1、获取CPU核心数量
    int iNumCpu = getCPUNum();

    // 2、配置限速
    m_iSpeed = 100;

    // 3、CPU数量为1,下面方式进行CPU限速将没有意义；
    if (iNumCpu <= 1) {
        m_iSpeed = iSpeed;
        if (checkProc() && m_pProc == NULL) {
            m_pProc = new ProcessEx();
            m_pProc->registerObserver(this);
            m_pProc->init(getpid());
        }

        return 1;
    }

    // 4、获取所需要的CPU核心数量
    switch(iSpeed) {
        case 25:
            {
                iNeedNumberOfProcessors = iNumCpu/4;
                if(iNeedNumberOfProcessors <= 0)
                {
                    iNeedNumberOfProcessors = iNumCpu/2;
                    m_iSpeed = 25;
                }
                break;
            }

        case 50:
            {
                iNeedNumberOfProcessors = iNumCpu/2;
                m_iSpeed = 50;
                break;
            }

        case 100:
            {
                iNeedNumberOfProcessors = iNumCpu;
                m_iSpeed = 100;
                break;
            }
        default:
            {
                LOG_INFO("unknown iSpeed %d", iSpeed);
                return 1;
            }
    }

    m_uCPUNum = iNeedNumberOfProcessors;
    CPU_ZERO(&mask);
    for(int i = 0; i < iNeedNumberOfProcessors; i++)
        CPU_SET(i, &mask);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        LOG_ERROR("sched_setaffinity() return error. errno:%d\t %s", errno, strerror(errno));
    } else {
        LOG_INFO("success to bind %d cpu.", m_uCPUNum);
    }

    if (iNumCpu == 2 && m_iSpeed == 25) {
        if(checkProc() && m_pProc == NULL) {
            m_pProc = new ProcessEx();
            m_pProc->registerObserver(this);
            m_pProc->init(getpid());
        } else {
            LOG_ERROR("system no /proc directory.");
        }
    }
    return 1;
}

int CPULimit::setSpeed(unsigned int iSpeed, pthread_t thread) {
    // 设置需要CPU核心数量
    int iNeedNumberOfProcessors = 0;

    // 设置掩码，不选择任何CPU核心
    cpu_set_t mask;

    // 1、获取CPU核心数量
    int iNumCpu = getCPUNum();
    m_cpunum = iNumCpu;
    if (m_cpunum <=0)
        m_cpunum = 1;

    // 2、配置限速
    m_iSpeed = 100;

    // 3、CPU数量为1,下面方式进行CPU限速将没有意义；
    if (iNumCpu <= 1) {
        m_iSpeed = iSpeed;
        LOG_INFO("set thread %ld, cpu %d\%, (success to start monitor)", thread, iSpeed);
        if (checkProc() && m_pProc == NULL) {
            m_pProc = new ProcessEx();
            m_pProc->registerObserver(this);
            m_pProc->init(getpid());
        }
        return 0;
    }

    // 4、获取所需要的CPU核心数量
    switch(iSpeed)
    {
        case 25:
            {
                iNeedNumberOfProcessors = iNumCpu/4;
                if(iNeedNumberOfProcessors <= 0)
                {
                    iNeedNumberOfProcessors = iNumCpu/2;
                    m_iSpeed = 25;
                }
                break;
            }

        case 50:
            {
                iNeedNumberOfProcessors = iNumCpu/2;
                m_iSpeed = 50;
                break;
            }

        case 100:
            {
                iNeedNumberOfProcessors = iNumCpu;
                m_iSpeed = 100;
                break;
            }
        default:
            {
                LOG_INFO("unknown iSpeed %d", iSpeed);
                return 0;
            }
    }

    CPU_ZERO(&mask);
    for(int i = 0; i < iNeedNumberOfProcessors; i++)
        CPU_SET(i, &mask);

    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &mask) != 0) {
        LOG_ERROR("pthread_setaffinity_np() return error. errno:%d\t %s", errno, strerror(errno));
        return -1;
    } else {
        m_uCPUNum = iNeedNumberOfProcessors;
        LOG_DEBUG("set thread %ld, cpu %d\%, (success to bind %d cpus)", thread, iSpeed, m_uCPUNum);
    }

    if (iNumCpu == 2 && m_iSpeed == 25) {
        if (checkProc() && m_pProc == NULL) {
            m_pProc = new ProcessEx();
            m_pProc->registerObserver(this);
            m_pProc->init(getpid());
        }
    } else {
        if (m_pProc != NULL)
            delete m_pProc;
        m_pProc = NULL;
    }

    return 0;
}

void CPULimit::update(double dParam) {
    m_dCPU = dParam;
}
