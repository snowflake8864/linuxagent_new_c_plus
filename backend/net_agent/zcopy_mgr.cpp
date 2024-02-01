#include <sys/stat.h>
#include <sys/types.h>

#include "zcopy_mgr.h"

//#ifdef USE_MMAP
#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif /* !MAP_FAILED */
//#endif /* USE MMAP */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/kernel/gnHead.h"
#include "common/log/log.h"
#define FILE_AUDIT_DATA_COUNT 4096
#define UIO_DEV "/dev/uio0"  
#define UIO_IN_NETLOG_AUDIT_ADDR "/sys/class/uio/uio0/maps/map0/addr"  
#define UIO_IN_NETLOG_AUDIT_SIZE "/sys/class/uio/uio0/maps/map0/size"  
#define UIO_OUT_NETLOG_AUDIT_ADDR "/sys/class/uio/uio0/maps/map1/addr"  
#define UIO_OUT_NETLOG_AUDIT_SIZE "/sys/class/uio/uio0/maps/map1/size"  
#define UIO_OPENPORT_NETLOG_AUDIT_ADDR "/sys/class/uio/uio0/maps/map2/addr"  
#define UIO_OPENPORT_NETLOG_AUDIT_SIZE "/sys/class/uio/uio0/maps/map2/size"  
#define UIO_DNS_NETLOG_AUDIT_ADDR "/sys/class/uio/uio0/maps/map3/addr"  
#define UIO_DNS_NETLOG_AUDIT_SIZE "/sys/class/uio/uio0/maps/map3/size"  



CZcopy_MGR::CZcopy_MGR()
{
	static char  in_netlog_size_buf[18];
	static char  in_netlog_addr_buf[18];
	static char  out_netlog_size_buf[18];
	static char  out_netlog_addr_buf[18];
	static char  openport_netlog_size_buf[18];
	static char  openport_netlog_addr_buf[18];
	static char  dns_netlog_size_buf[18];
	static char  dns_netlog_addr_buf[18];

    size_t page_size = getpagesize();
    in_netlog_audit_succeed = false; 
    out_netlog_audit_succeed = false; 
    openport_netlog_audit_succeed = false; 
    dns_netlog_audit_succeed = false; 
    in_netlog_audit_addr_fd = -1;
    in_netlog_audit_size_fd = -1;
    out_netlog_audit_addr_fd = -1;
    out_netlog_audit_size_fd = -1;
    openport_netlog_audit_addr_fd = -1;
    openport_netlog_audit_size_fd = -1;
    dns_netlog_audit_addr_fd = -1;
    dns_netlog_audit_size_fd = -1;
    uio_fd = -1;
	uio_fd = open(UIO_DEV, O_RDWR);

    if (uio_fd < 0) {
		fprintf(stderr, "mmap: %s\n", strerror(errno));  
		return;  
    }

    in_netlog_audit_addr_fd = open(UIO_IN_NETLOG_AUDIT_ADDR, O_RDONLY);
    in_netlog_audit_size_fd = open(UIO_IN_NETLOG_AUDIT_SIZE, O_RDONLY);
    out_netlog_audit_addr_fd = open(UIO_OUT_NETLOG_AUDIT_ADDR, O_RDONLY);
    out_netlog_audit_size_fd = open(UIO_OUT_NETLOG_AUDIT_SIZE, O_RDONLY);
    openport_netlog_audit_addr_fd = open(UIO_OPENPORT_NETLOG_AUDIT_ADDR, O_RDONLY);
    openport_netlog_audit_size_fd = open(UIO_OPENPORT_NETLOG_AUDIT_SIZE, O_RDONLY);
    dns_netlog_audit_addr_fd = open(UIO_DNS_NETLOG_AUDIT_ADDR, O_RDONLY);
    dns_netlog_audit_size_fd = open(UIO_DNS_NETLOG_AUDIT_SIZE, O_RDONLY);
    
    ssize_t nread = 0;
    if (in_netlog_audit_addr_fd > 0 && in_netlog_audit_size_fd > 0) {
        memset(in_netlog_addr_buf, 0, sizeof(in_netlog_addr_buf));
	    nread = ::read(in_netlog_audit_addr_fd,  in_netlog_addr_buf, sizeof(in_netlog_addr_buf));
        if (nread > 0) {
	        //in_netlog_audit_addr = (void *)strtol(in_netlog_addr_buf, NULL, 0);
            ::sscanf(in_netlog_addr_buf, "%llx", &in_netlog_audit_addr);
        } else {
            goto in_netlog_audit_out;
        }
        memset(in_netlog_size_buf, 0, sizeof(in_netlog_size_buf));
	    nread = ::read(in_netlog_audit_size_fd, in_netlog_size_buf, sizeof(in_netlog_size_buf));
        if (nread > 0) {
	        //in_netlog_audit_size = (size_t)strtol(in_netlog_size_buf, NULL, 0);
            ::sscanf(in_netlog_size_buf, "%llx", &in_netlog_audit_size);
	        in_netlog_audit_total_count = in_netlog_audit_size/sizeof(struct osec_network_report );
            in_netlog_cir_buffer = mmap(NULL, in_netlog_audit_size, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, /*in_netlog_audit_addr*/0);
            LOG_INFO("in_netlog_cir_buffer addr %p, size:%d\n",in_netlog_cir_buffer, in_netlog_audit_total_count);
            if (in_netlog_cir_buffer == MAP_FAILED) {
                LOG_ERROR("Error mapping UIO device memory for in netlog");
                close(in_netlog_audit_size_fd);
            } else {
                in_netlog_audit_succeed = true; 
            }

        }
    }
in_netlog_audit_out: 
#if 1
    if (in_netlog_audit_addr_fd > 0) {
        close(in_netlog_audit_addr_fd);
        in_netlog_audit_addr_fd = -1;
    }
    if (in_netlog_audit_size_fd > 0) {
        close(in_netlog_audit_size_fd);
        in_netlog_audit_size_fd = -1;
    }
#endif
    //
    if (out_netlog_audit_addr_fd > 0 && out_netlog_audit_size_fd > 0) {
        memset(out_netlog_addr_buf, 0, sizeof(out_netlog_addr_buf));
	    nread = ::read(out_netlog_audit_addr_fd,  out_netlog_addr_buf, sizeof(out_netlog_addr_buf));
        if (nread > 0) {
	        //out_netlog_audit_addr = (void *)strtol(out_netlog_addr_buf, NULL, 0);
            ::sscanf(out_netlog_addr_buf, "%llx", &out_netlog_audit_addr);
        } else {
            goto out_netlog_audit_out;
        }
        memset(out_netlog_size_buf, 0, sizeof(out_netlog_size_buf));
	    nread = ::read(out_netlog_audit_size_fd,  out_netlog_size_buf, sizeof(out_netlog_size_buf));
        if (nread > 0) {
	        //out_netlog_audit_size = (size_t)strtol(out_netlog_size_buf, NULL, 0);
            ::sscanf(out_netlog_size_buf, "%llx", &out_netlog_audit_size);
	        out_netlog_audit_total_count = out_netlog_audit_size/sizeof(struct osec_network_report );
            out_netlog_cir_buffer = mmap(NULL, out_netlog_audit_size, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, 1 * page_size);
            LOG_INFO("out_netlog_cir_buffer addr %p, count:%d\n",out_netlog_cir_buffer, out_netlog_audit_total_count);
            if (out_netlog_cir_buffer == MAP_FAILED) {
                LOG_ERROR("Error mapping UIO device memory for out netlog");
                //close(out_netlog_audit_size_fd);
            } else {
                out_netlog_audit_succeed = true; 
            }

        }
    }
out_netlog_audit_out: 
#if 1
    if (out_netlog_audit_addr_fd > 0) {
        close(out_netlog_audit_addr_fd);
        out_netlog_audit_addr_fd = -1;
    }
    if (out_netlog_audit_size_fd > 0) {
        close(out_netlog_audit_size_fd);
        out_netlog_audit_size_fd = -1;
    }
#endif
//
    if (openport_netlog_audit_addr_fd > 0 && openport_netlog_audit_size_fd > 0) {
        memset(openport_netlog_addr_buf, 0, sizeof(openport_netlog_addr_buf));
	    nread = ::read(openport_netlog_audit_addr_fd,  openport_netlog_addr_buf, sizeof(openport_netlog_addr_buf));
        if (nread > 0) {
	        //openport_netlog_audit_addr = (void *)strtol(openport_netlog_addr_buf, NULL, 0);
            ::sscanf(openport_netlog_addr_buf, "%llx", &openport_netlog_audit_addr);
        } else {
            goto openport_netlog_audit_out;
        }
        memset(openport_netlog_size_buf, 0, sizeof(openport_netlog_size_buf));
	    nread = ::read(openport_netlog_audit_size_fd,  openport_netlog_size_buf, sizeof(openport_netlog_size_buf));
        if (nread > 0) {
	        //openport_netlog_audit_size = (size_t)strtol(openport_netlog_size_buf, NULL, 0);
            ::sscanf(openport_netlog_size_buf, "%llx", &openport_netlog_audit_size);
	        openport_netlog_audit_total_count = openport_netlog_audit_size/sizeof(struct osec_openport_report );
            openport_netlog_cir_buffer = mmap(NULL, openport_netlog_audit_size, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, 2 * page_size);
            LOG_INFO("openport_netlog_cir_buffer addr %p,count:%d,openport_netlog_audit_addr:%p\n",openport_netlog_cir_buffer, openport_netlog_audit_total_count,openport_netlog_audit_addr);
            if (openport_netlog_cir_buffer == MAP_FAILED) {
                LOG_ERROR("Error mapping UIO device memory for openport netlog");
                close(openport_netlog_audit_size_fd);
            } else {
                openport_netlog_audit_succeed = true; 
            }

        }
    }
openport_netlog_audit_out: 
#if 1
    if (openport_netlog_audit_addr_fd > 0) {
        close(openport_netlog_audit_addr_fd);
        openport_netlog_audit_addr_fd = -1;
    }
    if (openport_netlog_audit_size_fd > 0) {
        close(openport_netlog_audit_size_fd);
        openport_netlog_audit_size_fd = -1;
    }
#endif
//////
    if (dns_netlog_audit_addr_fd > 0 && dns_netlog_audit_size_fd > 0) {
        memset(dns_netlog_addr_buf, 0, sizeof(dns_netlog_addr_buf));
	    nread = ::read(dns_netlog_audit_addr_fd,  dns_netlog_addr_buf, sizeof(dns_netlog_addr_buf));
        if (nread > 0) {
	        //openport_netlog_audit_addr = (void *)strtol(openport_netlog_addr_buf, NULL, 0);
            ::sscanf(dns_netlog_addr_buf, "%llx", &dns_netlog_audit_addr);
        } else {
            goto dns_netlog_audit_out;
        }
        memset(dns_netlog_size_buf, 0, sizeof(dns_netlog_size_buf));
	    nread = ::read(dns_netlog_audit_size_fd,  dns_netlog_size_buf, sizeof(dns_netlog_size_buf));
        if (nread > 0) {
	        //openport_netlog_audit_size = (size_t)strtol(openport_netlog_size_buf, NULL, 0);
            ::sscanf(dns_netlog_size_buf, "%llx", &dns_netlog_audit_size);
	        dns_netlog_audit_total_count = dns_netlog_audit_size/sizeof(struct osec_dns_report );
            dns_netlog_cir_buffer = mmap(NULL, dns_netlog_audit_size, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, 3 * page_size);
            LOG_INFO("dns_netlog_cir_buffer addr %p,count:%d,dns_netlog_audit_addr:%p\n",dns_netlog_cir_buffer, dns_netlog_audit_total_count,dns_netlog_audit_addr);
            if (dns_netlog_cir_buffer == MAP_FAILED) {
                LOG_ERROR("Error mapping UIO device memory for dns netlog");
                close(dns_netlog_audit_size_fd);
            } else {
                dns_netlog_audit_succeed = true; 
            }

        }
    }
dns_netlog_audit_out: 
#if 1
    if (dns_netlog_audit_addr_fd > 0) {
        close(dns_netlog_audit_addr_fd);
        dns_netlog_audit_addr_fd = -1;
    }
    if (dns_netlog_audit_size_fd > 0) {
        close(dns_netlog_audit_size_fd);
        dns_netlog_audit_size_fd = -1;
    }
#endif
}

CZcopy_MGR::~CZcopy_MGR()
{
	if (in_netlog_cir_buffer != MAP_FAILED)
	    munmap(in_netlog_cir_buffer, in_netlog_audit_size);
	if (out_netlog_cir_buffer != MAP_FAILED)
	    munmap(out_netlog_cir_buffer, out_netlog_audit_size);
    if (openport_netlog_cir_buffer != MAP_FAILED)
	    munmap(openport_netlog_cir_buffer, openport_netlog_audit_size);
    if (dns_netlog_cir_buffer != MAP_FAILED)
	    munmap(dns_netlog_cir_buffer, dns_netlog_audit_size);
        if (uio_fd != -1) 
		    close(uio_fd);
        if (in_netlog_audit_size_fd != -1) 
		    close(in_netlog_audit_size_fd);
        if (in_netlog_audit_addr_fd != -1) 
		    close(in_netlog_audit_addr_fd);

        if (out_netlog_audit_size_fd != -1) 
		    close(out_netlog_audit_size_fd);
        if (out_netlog_audit_addr_fd != -1) 
		    close(out_netlog_audit_addr_fd);

        if (openport_netlog_audit_size_fd != -1) 
		    close(openport_netlog_audit_size_fd);
        if (openport_netlog_audit_addr_fd != -1) 
		    close(openport_netlog_audit_addr_fd);

        if (dns_netlog_audit_size_fd != -1) 
		    close(dns_netlog_audit_size_fd);
        if (dns_netlog_audit_addr_fd != -1) 
		    close(dns_netlog_audit_addr_fd);

}


struct osec_network_report *CZcopy_MGR::getInNetLogAuditData(int idx)
{
	return (struct osec_network_report *)in_netlog_cir_buffer + (idx % in_netlog_audit_total_count);
}

struct osec_network_report *CZcopy_MGR::getOutNetLogAuditData(int idx)
{
	return (struct osec_network_report *)out_netlog_cir_buffer + (idx % out_netlog_audit_total_count);
}

struct osec_openport_report *CZcopy_MGR::getOpenPortLogAuditData(int idx)
{
	return (struct osec_openport_report *)openport_netlog_cir_buffer + (idx % openport_netlog_audit_total_count);
}

struct osec_dns_report *CZcopy_MGR::getDnsLogAuditData(int idx)
{
	return (struct osec_dns_report *)dns_netlog_cir_buffer + (idx % dns_netlog_audit_total_count);
}
