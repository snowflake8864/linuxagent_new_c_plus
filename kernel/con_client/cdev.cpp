#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include "CKTransferProxy.h"
#include "CKernelConnector.h"
#include "log/log.h"
#include "CKComm.h"
#include "cdev.h"
#include "gnHead.h"

static int cdev_fd = -1;
static pthread_t th_listen;

static int get_cdev_id(const char* cdev_name,dev_t& dev_id)
{
    int maj = 0;
    FILE* fp = NULL;
    bool found = false;
    char name[128] = {0};
    char buf[256] = {0};

    fp = fopen("/proc/devices","r");
    if(!fp) {
        LOG_ERROR("cdev: failed to read devices,"
            "because: %s",strerror(errno));
        return -1;
    }

    //skip the first line
    char* p = fgets(buf,sizeof(buf),fp);
    while((p = fgets(buf,sizeof(buf),fp))) {
        maj = 0;
        memset(name,0,sizeof(name));

        int n = sscanf(buf,"%d%s",&maj,name);
        memset(buf,0,sizeof(buf));
        if(n != 2) { continue; }
        
        found = !strcmp(name,cdev_name);
        if(found) { break; }
    }
    fclose(fp);

    if(!found) { 
        LOG_ERROR("cdev: can't find cdev: %s,"
            "the kernel module mayn't been loaded\n",cdev_name);
        return -1; 
    }

    dev_id = makedev(maj,0);
    return 0;
}

static int make_cdev_file(const char* cdev_path,const dev_t& dev_id)
{
    int rc = 0;
   
    mode_t mode = (S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP);
    rc = mknod(cdev_path,mode,dev_id);
    if(rc < 0 && (errno == EEXIST)) {
        rc = 0;
    }
    if(rc == 0) { return rc; }

    LOG_ERROR("cdev: failed make cdev file: %s,because: %s\n",
            cdev_path,strerror(errno));

    return rc;
}

static int open_cdev_file(const char* cdev_path)
{
    int fd = open(cdev_path,O_RDWR);
    if (fd < 0)
    {
        LOG_ERROR("cdev_init: failed open %s,because: %s",
            cdev_path,strerror(errno));
        return KTQ_EFAIL;
    }

    CKComm::set_fd_nonblock(fd);
    CKComm::set_fd_cloexec(fd);

    return fd;
}

static int do_init(const char* cdev_name)
{
    dev_t dev_id;
    std::string cdev_path;

    if(!cdev_name) {
        cdev_name = KTQ_CDEV_NAME; 
    }
    cdev_path = std::string("/dev/") + cdev_name;

    int rc = get_cdev_id(cdev_name,dev_id);
    if(rc) { return 
    KTQ_EFAIL; }

    rc = make_cdev_file(cdev_path.c_str(),dev_id);
    if(rc) { return KTQ_EFAIL; }
    
    int fd = open_cdev_file(cdev_path.c_str());
    if(fd < 0) { return KTQ_EFAIL; }

    cdev_fd = fd;

    return KTQ_OK;
}

static pid_t mygettid() 
{
#ifdef _GNU_SOURCE
    return syscall(SYS_gettid);
#else
    return gettid();
#endif
}

static void *cdev_listen_thread(void *arg)
{
    long tid = (long)mygettid();

    LOG_INFO("cdev listen thread %ld start\n",tid);
	epoll_func_listen_run();
    LOG_INFO("cdev listen thread %ld exit\n",tid);
	return NULL;
}

static int cdev_create_recv_thread(void)
{
	int rc = 0;
    memset(&th_listen,0,sizeof(th_listen));
    rc = pthread_create(&th_listen, NULL,cdev_listen_thread, NULL);

	if (0 > rc)
	{
		LOG_ERROR_SYS("cdev create recv thread failed,"
            "because: %s\n",strerror(rc));
        rc = KTQ_EFAIL;
	}
	
	return KTQ_OK;
}

void cdev_destroy()
{
    if(cdev_fd < 0) { 
        return; 
    }

    close(cdev_fd);
    cdev_fd = -1;

    pthread_t null_th;
    memset(&null_th,0,sizeof(null_th));
	if(!pthread_equal(null_th,th_listen)) {
		pthread_join(th_listen,NULL);
		memset(&th_listen,0,sizeof(th_listen));
	}

	LOG_INFO("cdev destroy");
}

static ssize_t cdev_send(int cmd,void* data,size_t len)
{
    int rc = len;
    kosecs_data_t kosecs_data;

    KTQ_SET_DATA(kosecs_data,cmd & 0xFFFF,len,(void*)data);

    //此处ioctl成功时返回的是大于0的值,是len + sizeof(kosecs_data)
    //由于kosecs_data是cdev自己做的封闭，所以此处成功时将len返回
    //不要直接返回ioctl的结果值
	int res = ioctl(cdev_fd,KTQ_IOC_SETVAL,&kosecs_data);
    if(res < 0) { rc = -1; }

    return rc;
}

static int cdev_reinit(int oldLstFd,void* data,void* ctx)
{
    int rc = -1;
    (void)oldLstFd;

    if(!data || !ctx) {
        return rc;
    }

    if(cdev_fd >= 0) {
        close(cdev_fd);
        cdev_fd = -1;
    }

    char* cdev_name = (char*)data;
    rc = do_init(cdev_name);
    if(rc) { 
        LOG_ERROR("cdev_reinit failed,"
        "because do_init failed,rc: %d",rc);
        return rc;
    }

    rc = epoll_func_reinit(cdev_fd,ctx);
    if(rc) {
        LOG_ERROR("cdev_reinit: "
            "epoll_func_reinit failed");
        close(cdev_fd);
        cdev_fd = -1;
    }

    LOG_INFO("cdev_reinit ok");

    return rc; 
}

#define cdev_read read;

static void cdev_set_ops(tp_ops_t* ops)
{
	ops->name = "cdev";
	ops->read = cdev_read;
	ops->send = cdev_send;
    ops->reinit = cdev_reinit;
	ops->release = cdev_destroy;
}

int cdev_init(const char* cdev_name,void* ctx,
            SW_EPOLL_CALLBACK_PF cb,
            SW_EPOLL_REINIT_FN reinit_cb,
            tp_ops_t* ops)
{
    if(cdev_fd >= 0) {
        LOG_ERROR("cdev_init failed,"
            "because cdev has been inited\n");
        return KTQ_EFAIL;
    }
    
    int rc = do_init(cdev_name);
    if(rc) { return rc; }

    cdev_set_ops(ops);

    rc = epoll_func_init(cdev_fd,ctx,cb,reinit_cb);
    if (-1 == rc)
    {
        cdev_destroy();
        return KTQ_EFAIL;
    }

    rc = cdev_create_recv_thread();
    if(rc) {
        cdev_destroy();
        return rc;
    }

    LOG_INFO("cdev initial ok");
    return rc;
}
