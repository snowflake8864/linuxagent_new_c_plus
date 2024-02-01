#ifndef PERFORMANCE_H
#define PERFORMANCE_H
#include "cpuinfo.h"
#include "meminfo.h"
#include <vector>
#include <list>
#include <string>

class CPerformance
{
	public:
		void getCpuInfo(double &nCpuPercent, long &nCpuTime);
		unsigned long getMemInfo();
		int getDiskInfo();
		std::string getboottime();
};

#endif //PERFORMANCE_H
