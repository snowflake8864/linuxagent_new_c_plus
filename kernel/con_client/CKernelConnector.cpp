#include <sys/socket.h>
#include <algorithm>
#include <errno.h>
#include <string.h>
#include <linux/netlink.h>
#include <fstream>
#include "CKernelConnector.h"
#include "CKoHelper.h"
#include "CKConnectorLog.h"
#include "CKTransferProxy.h"
#include "CKernelMsg.h"
#include "CKCmdHandlers.h"
#include "common/ini_parser.h"
#include "common/utils/string_utils.hpp"

static const char* DEF_CONF_FILE = "osec_kernel.conf";
#ifndef DRIVER_NAME
static const char* DRIVER_NAME = "osec_base";
static const char* UIO_DRIVER_NAME = "uio";
#endif

#define SUPPORT_DRIVER_VERSION1 "1.0.0.1000"
#define SUPPORT_DRIVER_VERSION2 "2.0.0.0000"
#define THREAD_CNT 4

#define INIT_STATUS_NOT_INIT 0
#define INIT_STATUS_INITED 1
#define INIT_STATUS_INITING 2
#define INIT_STATUS_RIGHT_VER 3
#define INIT_STATUS_WRONG_VER 4

#if defined(__GNUC__) && \
    ((__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
#define VISIBILITY_DEFAULT __attribute__((visibility("default")))
#else
#define VISIBILITY_DEFAULT
#endif


#define CMD_ARRAY_SIZE (NL_MAX_INDEX-(NL_POLICY_CMD_NOTIFY-1))
#define INDEX_TO_ARRAY(cmd) (cmd-NL_POLICY_CMD_NOTIFY)

static volatile int production_status = NL_PRODUCTION_EMPTY;

VISIBILITY_DEFAULT void CreateInstance(IKernelConnector** pKernelConnector)
{
    if (Singleton<CKernelConnector>::Init()) {
        Singleton<CKernelConnector>::Instance().AddRef();
        *pKernelConnector = &(Singleton<CKernelConnector>::Instance());
    }
}

static void data_ready_cb(void* data,size_t data_len,void* ctx)
{
    CKernelConnector* pthis = NULL;
    
    pthis = (CKernelConnector*)ctx;
    pthis->DoRecvKylinMsg(data);
}

CKernelConnector::CKernelConnector()
    : m_ref_cnt(0)
    ,m_init_status(INIT_STATUS_NOT_INIT)
    ,m_proxy(NULL)
{
    this->m_nProtocol = 20;
    m_cdevName = KTQ_CDEV_NAME;
}

CKernelConnector::~CKernelConnector() { uninit(); }
int CKernelConnector::AddRef()
{
    LOG_DEBUG("KernelConnector addref");
    return __sync_fetch_and_add(&m_ref_cnt, 1);
}

void CKernelConnector::Release()
{
    if (__sync_sub_and_fetch(&m_ref_cnt, 1) == 0) {
        Singleton<CKernelConnector>::Uninit();
    }
}

int CKernelConnector::RegisterProduct(NL_PRODUCTION product)
{
    if (m_init_status == INIT_STATUS_INITED) {
        SendMsgKBuf(NL_POLICY_CMD_REGISTER, &product, sizeof(product));

        int try_times = 0;
        while ((((int)production_status&(int)product) == 0) && try_times < 1000) {
            usleep(100);
            ++try_times;
        }
        return 0;
    }
    return -1;
}

int CKernelConnector::UnregisterProduct(NL_PRODUCTION product)
{
    int rc = KTQ_ENOTINIT;
    if(m_init_status == INIT_STATUS_INITED) {
        rc = SendMsgKBuf(NL_POLICY_CMD_UNREGISTER,
                    &product, sizeof(product));
    }

    return rc;
}

int CKernelConnector::initCmdHandlers()
{
    int rc = KTQ_OK;
    CKCmdHandlers* pHandlers = NULL;
    m_handlers.resize(CMD_ARRAY_SIZE,NULL);

    for(size_t i = 0;i < m_handlers.size();i++) {
        pHandlers = new (std::nothrow) CKCmdHandlers;
        if(!pHandlers) { rc = KTQ_ENOMEM; break; }
        m_handlers[i] = pHandlers;
    }

    if(rc) { uninitCmdHandlers(); }

    return rc;
}

void CKernelConnector::uninitCmdHandlers()
{
    for(size_t i = 0;i < m_handlers.size();i++) {
        delete m_handlers[i];
    }
    m_handlers.clear();
}

int ProductionHandler(NLPolicyType cmd, IKernelMsg* rec_kernel_msg, void* para)
{
    size_t  attr_len;
    production_status |= *(NL_PRODUCTION*)rec_kernel_msg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG, attr_len);
    LOG_INFO("reply production status:%d\n", production_status);

    return 0;
}

int CKernelConnector::Init()
{
    if (m_init_status == INIT_STATUS_INITED) {
        return KTQ_OK;
    }

    int ret = initInner();
    if (ret == KTQ_OK) {
        RegCmdHandler("con_client",
                      NL_POLICY_CMD_REGISTERED_NOTIFY,
                      3,
                      ProductionHandler,
                      NULL);

    }

    return ret;
}

//此处只所以从sysfs中读取一下: 主要是我们无法完全确认m_nProtocol的值是否是内核创建的netlink protocol
//因为: 在有些系统上我们在加载内核时指定的protocol会重复，出现这种情况内核模块会循环尝试使用另外的protcol值
//所以在此处我们根据内核模块导出的接口读取一次,做一下修正
static int readSysfsProto(int& nl_proto,std::string& cdev_name)
{
    int rc = -1;
    int fd = -1;
    char buf[1024] = {0};
    const char* sysfs_file = KTQ_SYSFS_PROTO;

    do {
        fd = ::open(sysfs_file,O_RDONLY);
        if(fd == -1) {
            LOG_ERROR("failed to open sysfs-file: %s,because: %s",
                        sysfs_file,strerror(errno));
            break;
        }

        ssize_t nread = ::read(fd,buf,sizeof(buf));
        if(nread <= 0) { break; }
        
        std::vector<std::string> strs;
        string_utils::Split(strs,buf,"\n");
        
        const char target1[] = "netlink:";
        size_t n1 = sizeof(target1) - 1;

        const char target2[] = "cdev:";
        size_t n2 = sizeof(target2) - 1;
        for(size_t i = 0;i < strs.size();i++) {
            if(!::strncmp(target1,strs[i].c_str(),n1)) {
                nl_proto = ::atoi(strs[i].c_str() + n1);
            } else if(!::strncmp(target2,strs[i].c_str(),n2)) {
                cdev_name = strs[i].substr(n2);
            }
        }

        LOG_INFO("load netlink protocol: %d,"
            "cdev: %s from sysfs file: %s\n",
            nl_proto,cdev_name.c_str(),sysfs_file);
        rc = 0;
    }while(false);
    ::close(fd);

    return rc;
}

int CKernelConnector::initKTransferProxy()
{
    void* data = NULL;
    int rc = KTQ_ENOMEM;
    int nl_protocol = m_nProtocol;
    std::string cdev_name = m_cdevName;

    readSysfsProto(nl_protocol,cdev_name);
    #ifdef OSECMJBZ
        int mode = TM_CDEV;
        data = &cdev_name;
    #else
        int mode = TM_NETLINK;
        data = &nl_protocol;     
    #endif

    m_proxy = new(std::nothrow)CKTransferProxy(mode,
                            this,data_ready_cb);
    if(m_proxy == NULL) { return rc; }

    rc = m_proxy->Init(data);
	if (rc != KTQ_OK) {
		delete m_proxy;
		m_proxy = NULL;

        m_init_status = INIT_STATUS_NOT_INIT;
        LOG_ERROR("CKernelConnector init ,"
            "init netlink failed. rc:(%d)" ,rc);
	}

    return rc;
}

void CKernelConnector::uninitKTransferProxy()
{
    if(!m_proxy) { return; }

    m_proxy->Uninit();
    delete m_proxy;
    m_proxy = NULL;
}

int CKernelConnector::initDispatchThreads()
{
    int rc = KTQ_OK;

    for (int i = 0; i < kDispatchThreadNum; ++i) {
        dispatch_threads_[i].SetThreadFunc(std::tr1::bind(
            &CKernelConnector::dispatchFun, this, std::tr1::placeholders::_1));
        dispatch_threads_[i].Run(dispatch_threads_ + i);
    }
    LOG_INFO("init dispatch threads");

    return rc;
}

void CKernelConnector::uninitDispatchThreads()
{
    for (int i = 0; i < kDispatchThreadNum; ++i) {
        dispatch_threads_[i].Quit();
    }
    data_queue_.BroadCast();

    for (int i = 0; i < kDispatchThreadNum; ++i) {
        dispatch_threads_[i].Join();
    }
    LOG_INFO("uninit dispatch threads");
}

int CKernelConnector::sendLSMSymsToKernel(void)
{
	int file_lines = 0;
	std::string buff = "";
	std::ifstream file("/opt/osec/");
	if (!file) {
		LOG_ERROR("sendLSMSymsToKernel open %s fail,err:%s \n", 
                "/opt/osec/Data/syms", strerror(errno));
		return KTQ_EFAIL;
	}

	while (getline(file, buff) && (file_lines < 20)) {
		std::vector<std::string> vec;
        string_utils::Split(vec, buff, " ");
		if (vec.size() != 3) {
			buff = "";
			continue;
		}
		int len = sizeof(struct symbol_msg) + vec[2].size()+1;
		struct symbol_msg *msg = (struct symbol_msg *)malloc(len);
		if (msg == NULL) {
			buff = "";
			continue;
		}
		memset(msg, 0, len);

        sscanf(vec[0].c_str(), "%lx", &msg->sym_addr);
		strncpy(msg->name, vec[2].c_str(), vec[2].size());
	
		if (m_proxy) {
			SendMsgKBuf(NL_POLICY_CMD_ADD_SYMBOL, (void *)msg, len);
		}
		free(msg);		
		buff = "";
		file_lines++;	
	}
	
	return KTQ_OK;	
}

//加载LSM符号初始化脚本
void CKernelConnector::initLSM()
{
    std::string symcmd= this->m_driverPath + "/syms.sh";
    if(access(symcmd.c_str(),F_OK)) {
        LOG_WARN("try to load LSM init script,"
            "but it's not existing");
        return;
    }

    int status = system(symcmd.c_str());
    if(status < 0) {
        LOG_TRACE("load LSM init script: %s failed,because: %s",
            symcmd.c_str(),strerror(errno));
    }
}

void CKernelConnector::initConfFile()
{
    char buf[1024] = {0};
    std::string cwd = getcwd(buf,sizeof(buf));
    if(!m_confFile.empty()) { return; }

    m_confFile = cwd + "/" + DEF_CONF_FILE;
}

static int getLogLevel(const char* slevel)
{
    int log_level = ASLog_Level_Trace;
    size_t size = sizeof(g_ASLogLevelString) /
                  sizeof(g_ASLogLevelString[0]);

    for(size_t i = ASLog_Level_Error;i < size;i++) {
        if(!strcmp(g_ASLogLevelString[i],slevel)) {
            log_level = i;
            break;
        }
    }
    
    return log_level;
}

void CKernelConnector::loadConfFile(int& log_level,std::string& log_path)
{
    INIParser parser;
    std::string conf_file = m_confFile;

    parser.ReadINI(conf_file);

    std::string level = parser.GetValue("LOG_CONF","LOGLEVEL");
    std::string path = parser.GetValue("LOG_CONF","LOGPATH");

    if(!path.empty()) { log_path = path; }
    if(!level.empty()) { log_level = getLogLevel(level.c_str()); }
}

void CKernelConnector::initLog(int log_level,const std::string& log_path)
{
    if(!log_path.empty()) {
        setLogInfo(ASLogLevel(log_level),log_path.c_str());
    }
    
    Singleton<CKConnectorLog>::Instance().Init();
}

void CKernelConnector::trySetDebugLog()
{
    bool bDebug = Singleton<CKConnectorLog>::Instance().isDebug();
    if (!bDebug) { return; }

    char buf[256] = {0};
    snprintf(buf,sizeof(buf),"%s1",
        ECHO_CMD_STR_SET_DEBUG);

    sendEchoStrMsg(buf);
}

int CKernelConnector::initInner()
{
    int ret = KTQ_EFAIL;
    std::string log_path;
    char str_opt[256] = {0};
    int log_level = ASLog_Level_Trace;

    snprintf(str_opt,sizeof(str_opt),
        "protocol=\"%d\" "
        "cdev_name=\"%s\"",
        m_nProtocol,m_cdevName.c_str());

    QH_THREAD::CWriteAutoLocker locker(&m_rwlock);
    if (m_init_status == INIT_STATUS_INITED) {
        return KTQ_OK;
    }

    initConfFile();
    loadConfFile(log_level,log_path);
    //先初始化日志
    initLog(log_level,log_path);
    initLSM();

    ret = initCmdHandlers();
    if(ret) { return ret; }

    ret = KTQ_ENOTROOT;
    if (getuid() != 0) {
        LOG_ERROR("init net link error, must root!");
        return ret;
    }
    ret = KTQ_EBADMOD;
    if (!CKoHelper::Modprobe(UIO_DRIVER_NAME,"")) {
        LOG_ERROR("load module name=%s error!",
                    UIO_DRIVER_NAME);
        return ret;
    } 
#if 0    
    if (!CKoHelper::LoadMod(DRIVER_NAME,m_driverPath.c_str(),str_opt)) {
        LOG_ERROR("load module name=%s,path=%s error!",
                    DRIVER_NAME,m_driverPath.c_str());
        return ret;
    }
#else 
#if 0
    ret = KTQ_EBADMOD;
    if (!CKoHelper::Modinfo(DRIVER_NAME,"")) {
        if (!CKoHelper::load_osec_base()) {
            return ret;
        }

        LOG_INFO("please depmod\n");
        CKoHelper::Depmod(); 
    }
    ret = KTQ_EBADMOD;
    if (!CKoHelper::Modprobe(DRIVER_NAME,"")) {
        LOG_ERROR("load module name=%s error!",
                    UIO_DRIVER_NAME);
        return ret;
    }
#else
    CKoHelper::ModMgr modMgr;
    ret = KTQ_EBADMOD;
    if (!modMgr.AutoLoadMod()) {
        LOG_ERROR("load module name=%s error!",
                    UIO_DRIVER_NAME);
        return ret;
    }
#endif
#endif

    m_init_status = INIT_STATUS_INITING;
    ret = initKTransferProxy();
    if(ret) { 
        m_init_status = INIT_STATUS_NOT_INIT;
        return ret; 
    }

    ret = initDispatchThreads();
    if(ret) {
        m_init_status = INIT_STATUS_NOT_INIT;
        return ret; 
    }

    //向内核发送LSM地址
//#ifndef OSECMJBZ
  //  sendLSMSymsToKernel();
//#endif
    //发送初始化命令
    sendEchoStrMsg(ECHO_CMD_STR_SET_PORT_ID);
    //等待驱动返回初始化信息
    int try_times = 0;
    while (m_init_status == INIT_STATUS_INITING && try_times < 1000) {
        usleep(100);
        ++try_times;
    }

    if (m_init_status == INIT_STATUS_RIGHT_VER) {
        ret = KTQ_OK;
        m_init_status = INIT_STATUS_INITED;
    } else if (m_init_status == INIT_STATUS_WRONG_VER) {
        LOG_DEBUG("wrong driver ver");
        ret = KTQ_EBADKVER;
    } else if (m_init_status == INIT_STATUS_INITING) {
        LOG_DEBUG("init timeout");
        ret = KTQ_ETIMEOUT;
    } else {
        LOG_DEBUG("init bug");
        ret = KTQ_EFAIL;
    }

    if (m_init_status != INIT_STATUS_INITED) {
        m_init_status = INIT_STATUS_NOT_INIT;
    }

    if (m_init_status == INIT_STATUS_NOT_INIT) {
        uninit();
    } else {
        trySetDebugLog();
        LOG_INFO("init success");
        ret = KTQ_OK;
    }

    return ret;
}

void* CKernelConnector::dispatchFun(void* para) {
    QH_THREAD::CWorkerThread* cur_thread_p =
        static_cast<QH_THREAD::CWorkerThread*>(para);
	LOG_INFO("%s:%s===>%d\n",__FILE__,  __FUNCTION__, __LINE__);
    while (!cur_thread_p->IsQuit()) {
		std::tr1::shared_ptr<void> msg;
		while (data_queue_.DeQueue(msg, 2000)) {
            struct kosecs_msg_data *data = NULL;
            data  = (struct kosecs_msg_data*)(msg.get());
			dispatchKylinMsg(data);
        }
    }
    return NULL;
}

int CKernelConnector::sendEchoStrMsg(const char* str) 
{
    ssize_t send_len = 0;
    if(!m_proxy) { return KTQ_EFAIL; }

    LOG_DEBUG("SendEchoMsg: %s\n", str);
    send_len = m_proxy->SendMsg2Kernel(NL_POLICY_CMD_ECHO, 
                            (void *)str, strlen(str) + 1);
    if (send_len < 0) {
        LOG_ERROR("SendEchoMsg %s fail\n", str);
        return KTQ_ESENDMSG;
    }
    return KTQ_OK;
}

int CKernelConnector::SendMsgKBuf(NLPolicyType cmd, void* buffer, int size)
{
    if(!m_proxy) { return KTQ_EFAIL; }

    LOG_DEBUG("SendBuffer %d\n", cmd);

    ssize_t send_len = m_proxy->SendMsg2Kernel(cmd, buffer, size);
    if (send_len < 0) {
        LOG_ERROR("CKernelConnector msg send buf, SendBuffer %d fail\n", cmd);
        return KTQ_ESENDMSG;
    }
    return KTQ_OK;
}

void CKernelConnector::uninit()
{
	if(m_proxy) {
		sendEchoStrMsg(ECHO_CMD_STR_CLEAR_PORT_ID);
		sleep(1);
		//stop epoll receive thread
		m_proxy->Stop(); 
	}

    uninitDispatchThreads();
    uninitCmdHandlers();
    uninitKTransferProxy();

#ifndef OSECMJBZ
    //密标专用机上不允许这样做
    CKoHelper::UnLoadMod(DRIVER_NAME);
#endif

    LOG_DEBUG("Uninit KernelConnector success");
    Singleton<CKConnectorLog>::Uninit();
    m_init_status = INIT_STATUS_NOT_INIT;
}

int CKernelConnector::DoRecvKylinMsg(void* pdata) {
    // return value not use by libnl, just return 0

	LOG_DEBUG("%s:%s===>%d\n",__FILE__,  __FUNCTION__, __LINE__);
	data_queue_.EnQueue(std::tr1::shared_ptr<void>(pdata, free));
    return 0;
}

int CKernelConnector::dispatchKylinMsg(struct kosecs_msg_data* msg) {
    int ret = KTQ_EFAIL;

	CKernelMsgSendCmd kmsg;

	kmsg.SetAttrMsg(NL_POLICY_ATTR_BIN_MSG,msg->data, msg->data_len);

	if (msg->data_type == NL_POLICY_CMD_ECHO) {  //处理Echo事件
        ret = handleEchoCmd(&kmsg);
    } else {  //处理其他事件
        ret = handleMsg((NLPolicyType)msg->data_type, &kmsg);
    }

    return ret;
}

int CKernelConnector::handleMsg(NLPolicyType cmd, IKernelMsg* kmsg) {
    int rc = KTQ_EBADCMD;
    if (cmd < NL_POLICY_CMD_NOTIFY || cmd >= NL_MAX_INDEX) {
        LOG_ERROR("CKernelConnector msg handle,"
            "unknown cmd %d", cmd);
        return rc;
    }

    int idx = INDEX_TO_ARRAY(cmd);

    LOG_DEBUG("recv cmd %d", cmd);
    rc = m_handlers[idx]->HandleKMsg(cmd,kmsg);
    return rc;
}

int CKernelConnector::handleEchoCmd(IKernelMsg* kmsg) 
{
    int rc = KTQ_OK;
    const char* data = NULL;

    do {
        if (m_init_status != INIT_STATUS_INITING) {
            break;
        }

        size_t attr_len = 0;
        data = kmsg->GetAttrMsg(NL_POLICY_ATTR_BIN_MSG,attr_len);

        /*兼容以前的旧内核通信模式,防止崩溃
         *内核发给应用层的ECHO数据中多了一个\0'
         *这个后续肯定要修改，内核与应用层的通信数据格式很多地方非常不合理
         */
        for(;data[attr_len - 1] == '\0';attr_len--);

        std::string value(data,attr_len);
        LOG_DEBUG("EVENT echo recv msg: %s",value.c_str());
        int nLen = strlen(ECHO_CMD_STR_SET_PORT_ID);
        if(strncmp(value.c_str(),ECHO_CMD_STR_SET_PORT_ID,nLen)) {
            m_init_status = INIT_STATUS_RIGHT_VER;
            break;
        }

        std::string driver_ver = value.substr(nLen);
        //应用层同时兼容1.0与2.0的驱动
        if ((driver_ver == SUPPORT_DRIVER_VERSION1) || 
            (driver_ver == SUPPORT_DRIVER_VERSION2)) {
            m_init_status = INIT_STATUS_RIGHT_VER;
        } else {
            m_init_status = INIT_STATUS_RIGHT_VER;
        }
    }while(false);

    return rc;
}

int CKernelConnector::RegCmdHandler(const char* module,
                                    NLPolicyType cmd, int priority,
                                    KernelCmdHandler handler, void* para)
{
    int rc = KTQ_EBADCMD;
    if (cmd < NL_POLICY_CMD_NOTIFY || cmd >= NL_MAX_INDEX)
    {
        LOG_ERROR("RegCmdHandler failed:"
            "bad cmd %d from module: %s",cmd,module);
        return rc;
    }

    int idx = INDEX_TO_ARRAY(cmd);
    rc = m_handlers[idx]->RegKCmdHandler(module,cmd,
                            priority,handler,para);
    return rc;
}

void CKernelConnector::UnRegCmdHandler(const char* module,
                                       NLPolicyType cmd) 
{
    if (cmd < NL_POLICY_CMD_NOTIFY || cmd >= NL_MAX_INDEX) {
        return;
    }

    int idx = INDEX_TO_ARRAY(cmd);
    (void)m_handlers[idx]->UnRegKCmdHandler(module,cmd);
}

int CKernelConnector::SetProtocol(int port)
{
    if (INIT_STATUS_INITED == m_init_status) {
        LOG_INFO("the kernel con client had been inited\n");
        return 0;
    }

    this->m_nProtocol = port;
    return 0;
}

int CKernelConnector::SetDriverPath(const char *path, int nForce)
{
    if (INIT_STATUS_INITED == m_init_status) {
        LOG_INFO("the kernel con client had been inited\n");
        return 0;
    }

    this->m_driverPath = path;
    this->m_nForce = nForce;
    return 0;
}

int CKernelConnector::SetChrDevName(const char* cdev_name)
{
    if (INIT_STATUS_INITED == m_init_status) {
        LOG_INFO("set chr device name failed:"
            "the kernel con client had been inited\n");
        return 0;
    }

    this->m_cdevName = cdev_name;

    return 0;
}

int CKernelConnector::setLogInfo(ASLogLevel level, const char* log_path)
{
    if (INIT_STATUS_INITED == m_init_status) {
        LOG_INFO("the kernel con client had been inited\n");
        return -1;
    }

    Singleton<CKConnectorLog>::Instance().SetLogLevel(level);
    Singleton<CKConnectorLog>::Instance().SetLogPath(log_path);

    return 0;
}

int CKernelConnector::EndWaiting(void* pwait_flag)
{
    return SendMsgKBuf(NL_POLICY_SIMPLE_END,
                                  (void*)&pwait_flag,
                                  sizeof(pwait_flag));
}

int CKernelConnector::EndBoolWaiting(void* pwait_flag, int bBool)
{

    struct bool_info re_info;
    re_info.pwait_flag = pwait_flag;
    re_info.bBool = bBool;

    return SendMsgKBuf(NL_POLICY_BOOL_END,
                                  (void*)&re_info,
                                  sizeof(re_info));
}

int CKernelConnector::SetConfFile(const char* conf_file)
{
    m_confFile = conf_file;
    return 0;
}
