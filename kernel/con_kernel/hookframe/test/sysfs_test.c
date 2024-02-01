#include "sysfs/khf_sysfs.h"
#include "core/khf_version.h"
#include "khookframe.h"

static ssize_t tq_version_show(struct kobject *kobj,struct attribute *attr,char *buf)
{
	ssize_t ret;
    const char* mod_ver = khf_get_version();
	ret = sprintf(buf,"name: %s\n%s\n",
                THIS_MODULE->name,mod_ver);
	return ret;
}
 
struct khf_sysfs_entry tq_version = 
	__ATTR(version,S_IRUGO,tq_version_show,NULL);

extern unsigned long debug_flag; 
static ssize_t tq_debug_show(struct kobject* kobj,struct attribute* attr,char* buf)
{
	ssize_t ret = 0;
    ret = sprintf(buf,"%lu",debug_flag);
    return ret;
}

static ssize_t tq_debug_store(struct kobject* kobj, struct attribute *attr,
	      					const char * buf, size_t len)
{
	char c;
	unsigned long val = 0;

	if(!buf || !len) {
		return -EINVAL;
	}

	if(len > 1) {
		return -E2BIG;
	}

	c = buf[0];
	if(c != '0' && c != '1') {
		return -EINVAL;
	} 

	val = c - '0';
	(void)xchg(&debug_flag,val);
	LOG_DEBUG("set debug_flag: %lu\n",val);
	
	return len;
}

struct khf_sysfs_entry tq_debug = 
	__ATTR(debug,S_IRUGO | S_IWUSR,tq_debug_show,tq_debug_store);

static ssize_t tq_switch_store(struct kobject* kobj, struct attribute *attr,
	      					const char * buf, size_t len)
{
	char c;
	unsigned long val = 0;

	if(!buf || !len) {
		return -EINVAL;
	}

	if(len > 1) {
		return -E2BIG;
	}

	c = buf[0];
	if(c != '0' && c != '1') {
		return -EINVAL;
	} 

	val = c - '0';
	if(val) {
		khf_hook_syscalls();
	} else {
		khf_cleanup_syscalls();
	}
	LOG_DEBUG("set debug_flag: %lu\n",val);
	
	return len;
}

struct khf_sysfs_entry tq_switch = 
	__ATTR(switch,S_IWUSR,NULL,tq_switch_store);

static struct attribute* sysfs_def_attr[] = {
	&tq_debug.attr,
	&tq_version.attr,
	&tq_switch.attr,
	NULL,
};

static struct attribute_group def_attr_group = {
	.attrs = sysfs_def_attr
};


void test_sysfs_init(void)
{
    khf_sysfs_init(KMOD_NAME,&def_attr_group);
}

void test_sysfs_uninit(void)
{
    khf_sysfs_uninit();
}
