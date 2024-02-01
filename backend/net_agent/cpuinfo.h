#ifndef CPUINFO_H
#define CPUINFO_H
#include <string>
#include <unistd.h>

struct CpuUseState
{
    char name[20];
    unsigned long long user;
    unsigned long long nice;
    unsigned long long system;
    unsigned long long idle;
    unsigned long long iowait;
    unsigned long long irq;
    unsigned long long  softirq;
    unsigned long long steal;
    unsigned long long guest;
    unsigned long long guest_nice;
    CpuUseState();
    CpuUseState(const CpuUseState&);
};

class CpuInfo
{
public:
    CpuInfo();
    ~CpuInfo() {;};
    void getCpuInfo(double *nCpuPercent);
    void setCalcFrequency(int iCalcFrequency);
    double getUsage();
private:
   int _getCpuUseState(CpuUseState& cpu_use);
   double _calcCpuUseState(const CpuUseState& o,const CpuUseState& n);
private:
    double _cpu_use;
    CpuUseState _last;//上一次CPU使用情况
    int m_iCalcFrequency;
};

std::string getCpuNum();
int getDiskInfo(double &totoal, double &usedPercent);
#endif // CPUINFO_H
