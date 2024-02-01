#include <linux/module.h>
#include <linux/types.h>
 #include <linux/proc_fs.h>
#include "utils/utils.h"
#include "conn_block_rules.h"
#include "dpi/dpi.h"
#include "core/zcopy.h"
#include "defense/defense_inner.h"
#include "utils/var_proc.h"

struct proc_dir_entry *proc_osec = NULL;
struct proc_dir_entry *proc_pattern_rules = NULL;
EXPORT_SYMBOL(proc_osec);
static int rules_init_finish = 0;

/*
 * Operations for setting or displaying block gateway.
 */
static int __self_build(char *buf, size_t buf_sz, void *info)
{
    if (is_self_enable() == 1) {
	    strcpy(buf, "system is in self protect\n");
    } else {
	    strcpy(buf, "system is out of  self protect\n");
    }
	return 0;
}
#include <linux/ktime.h>  
#include <linux/string.h>  
#include <linux/time.h>  
#include <linux/ktime.h>  
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include "gnHead.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void get_date(time64_t timestamp, char *d_buf) 
{
    const int days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int seconds_in_day = 24 * 60 * 60;
    int days = timestamp / seconds_in_day;
    int year = 1970; //起始年份为1970年  
    int month = 0;
    int day = 0;

    while (days >= 0) {
        int leap_year = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        if (leap_year && month == 1) {
            days -= 29;
            month++;
        } else {
            days -= days_in_month[month];
            month++;
        }
        if (month > 11) {
            year++;
            month = 0;
        }
    }

    day = days_in_month[month] + (days + 1);
    //month++;
    snprintf(d_buf, 32, "%d%d%d",year,month, day);
}
#endif


static int __self_parse(const char *buf, void *info)
{
    int enable = 0;
    char veda[16] = {0};
    uint32_t date;
	if(sscanf(buf, "%s %d %d\n", veda, &date, &enable) != 3)
	{
        return 0;
	}
    char d_buf[32] = {0};
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    struct timex  txc;
    struct rtc_time tm;
    do_gettimeofday(&(txc.time));
    rtc_time_to_tm(txc.time.tv_sec,&tm);
    snprintf(d_buf, 32, "%d%d%d",tm.tm_year+1900,tm.tm_mon + 1, tm.tm_mday);
#else
    struct tm tm;  
    time64_t timestamp;  

    /* 获取当前时间戳 */  
    timestamp = ktime_get_real_seconds();  
    get_date(timestamp, d_buf); 
#endif
    
    uint32_t u = 0;
	if(sscanf(d_buf, "%u", &u) != 1) {
        return 0;
    }
    if (memcmp(CURRENT_COMM, "MagicArmor_0", 12) == 0) {
        if (strncmp(veda, "veda", 4) == 0) {
            LOG_INFO("set self prote========[%s]\n", CURRENT_COMM);
            if (enable == 1) {
                turn_on_self();
            } else {
                turn_off_self();
            }
        }
        return 0;
    }

    //LOG_INFO("current date:%u, user date:%u\n", u, date); 
    if (strncmp(veda, "veda", 4) == 0 &&u + 1  == date) {
        LOG_INFO("set self prote========[%s]\n", CURRENT_COMM);
        if (enable == 1) {
            turn_on_self();
        } else {
            turn_off_self();
        }
    }
	return 0;
}
static struct var_proc_info self_vinfo =
{
	.parse = __self_parse,
	.build = __self_build,
};


int rules_init(void)
{
    int retv = 0;
    /* Create a 'proc_fs' container directory */
    if((proc_osec = proc_mkdir("osec", NULL)) == NULL)
    {
        printk(KERN_ERR "osec_base: Cannot create directory '/proc/osec'.\n");
        retv = -1;
        goto err1; 
    }
	if((retv = conn_block_init(proc_osec)) == -1) {
       goto err2;
    }
    retv = zcopy_init(proc_osec);
    if (retv) {
        goto err3;
    }

    if ((retv = dpi_init(proc_osec)) == -1) {
        goto err4;
    }
	var_proc_create("self", proc_osec, &self_vinfo);	
    rules_init_finish = 1;
    return retv;
err4:
    zcopy_exit(proc_osec);
err3:
    conn_block_exit(proc_osec);
err2:
    remove_proc_entry("osec", NULL);
err1:
    return retv;
}

void rules_exit(void)
{

    if (rules_init_finish != 1) {
        return;
    }

	var_proc_remove("self", proc_osec);
    dpi_exit(proc_osec);
    zcopy_exit(proc_osec);
    conn_block_exit(proc_osec);
    remove_proc_entry("osec", NULL);
}
