#ifndef MEMINFO_H
#define MEMINFO_H


class MemInfo
{
public:
    MemInfo();
    ~MemInfo() {};
    void getMemInfo(int *nCpuPercent);
    int _getMemUseState(unsigned long& total_mem,unsigned long & mem_used);
private:
    unsigned long _total_mem;//内在总量
    unsigned long _mem_used;//已使用量
};

#endif // MEMINFO_H
