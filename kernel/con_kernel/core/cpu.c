#include <linux/cpumask.h>
#include "gnHead.h"
#include "cpu.h"

//当前系统上的cpu数,至少有一颗
int ktq_nr_cpus = 1; 

void ktq_cpu_init(void)
{
    ktq_nr_cpus = num_possible_cpus();
    LOG_INFO("the system has %d possible cpus\n",
        ktq_nr_cpus);
}

void ktq_cpu_uninit(void)
{}