#ifndef CPU_LIMIT_CPULIMIT_H
#define CPU_LIMIT_CPULIMIT_H
#include <unistd.h>
#include "process.h"
#include "singleton.hpp"

class CPULimit : public Observer {
  public:
    CPULimit();
    ~CPULimit();

    void init();
    void uninit();
    int start(unsigned int iSpeed);
    int setSpeed(unsigned int iSpeed, pthread_t thread);
    int stop();
    int monitor();
    int monitorCPUNum();
    unsigned int getBindCPUNum();

    void update(double dParam);

  private:
    int setSpeedType(unsigned int iSpeed);
    int getCPUNum();
    int checkProc();

  private:
    unsigned int m_iSpeed; // current cpu's limit speed
    double m_dCPU;
    unsigned int m_uCPUNum; // the number of cpu
    ProcessEx* m_pProc;
    int m_cpunum;
    pid_t    m_pid;
};

#endif /* CPU_LIMIT_CPULIMIT_H */
