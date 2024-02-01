#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

//#include "common/singleton.hpp"
#include "conn_block_mgr.h"
#include "common/kernel/gnHead.h"
#include "common/log/log.h"

#define BLOCK_PROC_FILE "/proc/osec/osec_conn/block_saddr_rt"
ConnBlock_MGR::ConnBlock_MGR()
{
#if 0
    fd = -1;
	fd = open(BLOCK_PROC_FILE, O_RDWR);
    if (fd < 0) {
		fprintf(stderr, "open fail: %s\n", strerror(errno));  
    }
    LOG_INFO("open proc %d is success\n",fd);
#endif
}

ConnBlock_MGR::~ConnBlock_MGR()
{
#if 0
    if (fd > 0) {
        close(fd);
    }
#endif
}
#if 0
int ConnBlock_MGR::Init()
{
    Singleton<ConnBlock_MGR>::Instance();
    return 0;
}
#endif
void ConnBlock_MGR::AddIP2BlockList(std::string& ip)
{
	int fd = open(BLOCK_PROC_FILE, O_RDWR);
    if (fd < 0) {
		fprintf(stderr, "open fail: %s\n", strerror(errno));  
		LOG_ERROR("open fail: %s\n", strerror(errno));  
    }

    ip.append("\n");
    LOG_INFO("add ip:%s to BlockList\n",ip.c_str());
    ::write(fd, ip.c_str(), ip.size());
    close(fd);
}
void ConnBlock_MGR::ClearBlockList()
{
	int fd = open(BLOCK_PROC_FILE, O_RDWR);
    if (fd < 0) {
		fprintf(stderr, "open fail: %s\n", strerror(errno));  
		LOG_ERROR("open fail: %s\n", strerror(errno));  
    }

    ::write(fd, "c\n", 2);
    close(fd);
}

