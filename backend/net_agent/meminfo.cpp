#include "meminfo.h"
#include <cstdio>
#include <errno.h>
#include <cstring>

MemInfo::MemInfo()
    : _total_mem(0),
    _mem_used(0)
    {}

int MemInfo::_getMemUseState(unsigned long& total_mem,unsigned long & mem_used)
{
    FILE *fd = NULL;
    char buff[256] = {0};
    char name[64] = {0};
    bool finish = false;
    bool read_total = false;
    bool read_free = false;
    bool read_buff = false;
    bool read_cache = false;

    fd = std::fopen ("/proc/meminfo", "r");
    if (fd == NULL) {
        //LOG_ERROR("failed to open the file: /proc/meminfo failed,because: %s"
        //    , std::strerror(errno));
        printf("MemInfo getting mem use state, failed to open the file. file:(/proc/meminfo), err:(%s)\n"
                , std::strerror(errno));
        return -1;
    }

    unsigned long value = 0;
    unsigned long mem_free = 0;
    unsigned long mem_buffer = 0;
    unsigned long mem_cache = 0;

    while ((!finish) && (fgets(buff,sizeof(buff),fd) != NULL)) {
	    std::sscanf (buff, "%s %lu",name,&value);
	    if (strcasecmp(name,"MemTotal:") == 0) {
		    total_mem = value;
		    read_total = true;
	    } else if (strcasecmp(name,"MemFree:") == 0) {
		    mem_free =value;
		    read_free = true;
	    } else if(strcasecmp(name,"Buffers:") == 0) {
		    mem_buffer = value;
		    read_buff = true;
	    } else if(strcasecmp(name,"Cached:") == 0) {
		    mem_cache = value;
		    read_cache = true;
	    }
	    bzero(buff,sizeof(buff));
	    finish = (read_total && read_free && read_buff && read_cache);
    }

    mem_used = total_mem - mem_free - mem_cache - mem_buffer;

    std::fclose(fd);

    return 0;
}

void MemInfo::getMemInfo(int *nMemPercent) {
	unsigned long total_mem = 0;
	unsigned long mem_used = 0;

	int rc = _getMemUseState(total_mem,mem_used);
	if(rc == -1) {
		//LOG_ERROR("_getMemUseState error.");
        printf("MemInfo getting mem info, Unable to get memory state\n");
		*nMemPercent = 0;
		return;
	}

	_mem_used = mem_used;
	_total_mem = total_mem;

	int mem_use_percent = (_mem_used * 100) / _total_mem;
	*nMemPercent = mem_use_percent;

}
