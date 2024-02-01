#ifndef GN_HEAD_H
#define GN_HEAD_H

#ifndef __KERNEL__
    //user-space
    #include <stdint.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <linux/types.h>
    #include <sys/socket.h>
    #include <time.h>
    #include <sys/time.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <sys/ioctl.h>
#else
    #include <linux/in.h>
    #include <linux/in6.h>
    #include <linux/time.h>
    #include <linux/types.h>
    #include <linux/version.h>
    #include <linux/if.h>
    #include <linux/coda.h>

    
    #define LOG_INFO(fmt, args...) printk(KERN_INFO "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
    #define LOG_ERROR(fmt, args...) printk(KERN_ERR "[%s][%d]: "fmt, __FUNCTION__, __LINE__, ##args)

	#ifdef DEBUG_FLAG
        extern unsigned long debug_flag;
        #ifdef DEBUG
            #define LOG_DEBUG(fmt, args...) printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
        #else
            #define LOG_DEBUG(fmt, args...) {if (test_bit(0,&debug_flag)) {printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__, ##args);}}
        #endif
    #else
        #ifdef DEBUG
            #define LOG_DEBUG(fmt, args...) printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args)
        #else
            #define LOG_DEBUG(fmt, args...) 
        #endif
    #endif

    #define LOG_ERROR_SELF(fmt, args...) printk(fmt, ##args)
    #define LOG_ERROR_SYS(fmt, args...) printk(fmt, ##args)
    #define LOG_ERROR_DEV(fmt, args...) printk(fmt, ##args)
#endif

typedef enum {
    NL_POLICY_ATTR_UNSPEC,
    NL_POLICY_ATTR_BIN_MSG,
    NL_POLICY_ATTR_STR_MSG,
    NL_POLICY_ATTR_WAIT_FLAG,
    NL_POLICY_ATTR_DATA_MSG,
    __NL_POLICY_ATTR_MAX,
} NL_POLICY_ATTR;

#define GN_POLICY_ATTR_MAX (__GN_POLICY_ATTR_MAX - 1)

typedef enum {
    NL_PRODUCTION_EMPTY = 0,
    NL_PRODUCTION_SELF = 1,
    NL_PRODUCTION_AV = 2,
    NL_PRODUCTION_APP_CONTROL = 4,
    NL_PRODUCTION_AUDIT = 8,
    NL_PRODUCTION_SEC_LABEL = 16,
    NL_PRODUCTION_DEVICE_CONTROL = 32,
    NL_PRODUCTION_NAC_WATER = 64,
    NL_PRODUCTION_NETWORK = 128,
    NL_PRODUCTION_MSTORAGE = 256, //mobile-storage
} NL_PRODUCTION;

/* commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be ececuted
 */
typedef enum {
    NL_POLICY_CMD_UNSPEC,
    NL_POLICY_CMD_ECHO = 1,
    NL_POLICY_SIMPLE_END,
    NL_POLICY_BOOL_END,
    NL_POLICY_CMD_REGISTER,
    NL_POLICY_CMD_ADD_SYMBOL,
    NL_POLICY_CMD_UNREGISTER,
    
//self protection notify index array
    NL_POLICY_DEFENSE_UNSPEC = 0x100,
    NL_POLICY_DEFENSE_SWITCHER,
    NL_POLICY_DEFENSE_ADD_WHITE_EXE,
//self protection notify index array
    NL_POLICY_SELF_SWITCHER,
    NL_POLICY_GLOBAL_DIR,
    NL_POLICY_EXIPORT_RULE,
    NL_POLICY_PROTECT_RULE,
    NL_POLICY_DEFENSE_FILE_PROCESS_POLICY,





//security document notify index array
    NL_POLICY_AUDIT_UNSPEC = 0x200,
    NL_POLICY_AUDIT_NET_POLICY,
    NL_POLICY_AUDIT_PROCESS_POLICY,
    NL_POLICY_AUDIT_SOFTWARE_POLICY,
    NL_POLICY_AUDIT_SERVERIP_POLICY,
    NL_POLICY_AUDIT_PRINT_POLICY,
    NL_POLICY_AUDIT_UDISK_POLICY,//for shield
    //黑名单ip策略(2020/10/19 AK6测试新增功能)
    //格式: |--2 bytes IP列表数量标识(为0时表示关闭，此时后面IP列表可有可无，内核自动忽略)--|--IP列表(ipv4地址整型表示，网络字节序)--|
    NL_POLICY_AUDIT_BLACK_IP,
    //AK6测评文件访问控制策略(8.0.5.0600)
    //格式: |--2 bytes 文件列表数量标识(为0时表示关闭，此时后面文件列表可有可无，内核自动忽略)--|--文件列表(以;分隔)--|
    NL_POLICY_AUDIT_FACCESS,
//security document notify index array
    NL_POLICY_SECLABEL_UNSPEC = 0x300,
    NL_POLICY_SECLABEL_PROCESS = 0x301,
    NL_POLICY_SECLABEL_FILE_REDIRECT,
    NL_POLICY_SECLABEL_SWITCHER,
    NL_POLICY_SECLABEL_SCR_OPER,
    NL_POLICY_SECLABEL_OPT_REDIRECT,
    NL_POLICY_SECLABEL_HOME_REDIRECT,
//anti virus notify index array
    NL_POLICY_SD_UNSPEC = 0x400,
    NL_POLICY_SD_SWITCHER,
    NL_POLICY_SD_ADD_EXEC_WHITE,
    NL_POLICY_SD_ADD_FILE_WHITE,
    NL_POLICY_SD_POLICY_WHITE_PATH, //策略路径白名单
    NL_POLICY_SD_POLICY_WHITE_EXT, //策略扩展名白名单
    NL_POLICY_SD_EXEC_SWITCH,//程序启动上报开关
    NL_POLICY_SD_FILE_SWITCH,//文件事件上报开关
    NL_POLICY_SD_WEXE_CACHE_SWITCH,//进程启动白名单缓存开关
    NL_POLICY_SD_WEXEC_CACHE_CLEAN,//清理进程启动白名单缓存
    
//device control
    NL_POLICY_DEVICE_CONTROL_UNSPEC = 0x500,
    NL_POLICY_DEVICE_CONTROL_POLICY,

    //nac water
    NL_POLICY_NAC_WATER_UNSPEC = 0x600,
    NL_POLICY_NAC_WATER_POLICY,

    //Mobile storage
    NL_POLICY_MSTORAGE_UNSPEC = 0x620,

//network change
    NL_POLICY_NETWORK_UNSPEC = 0x700,
    NL_POLICY_NETWORK_POLICY,
    NL_POLICY_NETWORK_SERVERIP_POLICY,
    NL_POLICY_NETWORK_NAC_SERVERIP_POLICY,
    NL_POLICY_NETWORK_DNSIP_POLICY,
    NL_POLICY_NETWORK_TLSIP_POLICY,

    NL_POLICY_NETSYSLOG_POLICY,
    NL_POLICY_NETWORK_NETBLOCK,
    NL_POLICY_NETWORK_BUSINESS_PORT_POLICY,

    NL_MAX_CLASSIC_INDEX,

/*
 *再添加内核发给应用层的通知，一定要向后加，不要再动以前的了
 *内核发给应用层的通知不要再在这里加了！！！！！！！！！！！！！
 *不然肯定会导致无法兼容以前的版本，引起程序崩溃消息无法正常处理等各种问题
 *后续对内核发给应用层的通知也要做分节处理
*/
////////////////////////////////////////////////////////////////////////////////
//kernel to client common
    NL_POLICY_CMD_NOTIFY = 0x503, //compatiable AK2
    //Note:内核发送给用户态的TLV通知,不要修改这个值，
    //后续内核发给用户态的TLV格式通知，全部会采用该值
    #define NL_NOTIFY_TLV NL_POLICY_CMD_NOTIFY
    NL_POLICY_CMD_REGISTERED_NOTIFY,
////////////////////////////////////////////////////////////////////////////////
//再添加内核发给应用层的通知，一定要向后加，不要再动以前的了
//内核发给应用层的通知不要再在这里加了！！！！！！！！！！！！！
//下面这些一直到NL_POLICY_NETWORK_DNSIP_NOTIFY都不要再动了!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//antivirus rtmonitor
    NL_POLICY_AV_PROCESS_EXEC_NOTIFY,
    NL_POLICY_AV_FILE_CHANGE_NOTIFY,
    NL_POLICY_AV_SELF_PROTECTION_NOTIFY,
    NL_POLICY_NET_PORT_NOTIFY,
    NL_POLICY_NET_PORT_ZCOPY_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_NOTIFY,
    NL_POLICY_NET_DNS_PORT_NOTIFY,
    NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY,

///////////////////////////////////////////////////////////////////////////////
//sec doc
    NL_POLICY_SECLABEL_FILE_OPEN_NOTIFY,
    NL_POLICY_SECLABEL_FILE_CLOSE_NOTIFY,
    NL_POLICY_SECLABEL_FILE_RENAME_NOTIFY,
    NL_POLICY_SECLABEL_TASK_EXIT_NOTIFY,
    NL_POLICY_SECLABEL_CONTROL_OPER_NOTIFY,
    NL_POLICY_SECLABEL_UNLINK_FILE_NOTIFY,
////////////////////////////////////////////////////////////////////////////////
//audit
    NL_POLICY_AUDIT_NETFLOW_NOTIFY,
    NL_POLICY_AUDIT_FLOWMONITOR_CTRL_NOTIFY,
    NL_POLICY_AUDIT_FLOWMONITOR_AUDIT_NOTIFY,
    NL_POLICY_AUDIT_ARP_NOTIFY,
    NL_POLICY_AUDIT_PORTSCAN_NOTIFY,
    NL_POLICY_AUDIT_HTTP_NOTIFY,
    NL_POLICY_AUDIT_PFLOW_NOTIFY,
    NL_POLICY_AUDIT_PORT_NOTIFY,
    NL_POLICY_AUDIT_FILE_NOTIFY,
    NL_POLICY_AUDIT_SERVICE_NOTIFY,
    NL_POLICY_AUDIT_SOFTWARE_NOTIFY,
    NL_POLICY_AUDIT_EXEC_CONTROL_NOTIFY,
    NL_POLICY_AUDIT_PRINTER_NOTIFY,
    NL_POLICY_AUDIT_UDISK_NOTIFY,//for shield
    
    //device control
    NL_POLICY_DEVICE_CONTROL_INQUIRY,

    //network change
    NL_POLICY_NETWORK_CHANGE_NOTIFY,
    NL_POLICY_NETWORK_DNSIP_NOTIFY,
    //上面这些都不要再动了!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    /////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////在这里向后每个分节中加!!!!!!!!!!!!!!//////////////////////////////////
    //内核发给应用层的通知在这里按照不同的分段加!!!!!!!!!!!!!!!
    //密标内核发给应用层的通知,2048-2147，一共100个,其他类型不要再占用这个区间了
    //sec doc copy file notify(为了保证向前兼容，我们将这个新值放在最后)
    NL_POLICY_SECLABEL_CP_FILE_NOTIFY = 0x800,
    //密标文件管理器write-close操作通知(为了保证向前兼容，我们将这个新值放在最后)
    NL_POLICY_SECLABEL_FILEMGR_WCLOSE_NOTIFY,
    //特殊格式压缩包重命名通知:file-roller,file-compress,对应扩展名格式:.iso,.tar
    NL_POLICY_SECLABEL_RENAME_SPECARCHIVE_NOTIFY,
    // 截屏或者录屏通知：发送结构体 sec_label_scr_info
    NL_POLICY_SECLABEL_SCREEN_SHOT_NOTIFY,
    NL_POLICY_SECLABEL_NOTIFY_MAX = 0x863,

    //AV内核发给应用层的通知2148-2247,一共100个,其他类型不要再占用这个区间了
    //内核发给应用层的文件变更事件(write-close)通知
    NL_POLICY_AV_FILE_FROM_CHANGE_NOTIFY = 0x864,
    //针对文件的utimes调用通知
    NL_POLICY_AV_UTIMES_NOTIFY,
    NL_POLICY_AV_NOTIFY_MAX = 0x8C7,

    //内核发给应用层的通用通知2248-2347,一共100个
    NL_POLICY_COM_MOUNT_NOTIFY = 0x8C8, //MOUNT通知
    NL_POLICY_COM_UMOUNT_NOTIFY,//UMOUNT通知
    NL_POLICY_COM_NOTIFY_MAX = 0x92B,

	//主审的内核通知:2348-2447,一其100个
	//zyj主审网络连接特定的消息宏
    NL_POLICY_AUDIT_NETFLOW_ZYJ_NOTIFY = 0x92C,//for shield
    NL_POLICY_AUDIT_PORT_NEW_NOTIFY, //AK7 audit_bind ports
    NL_POLICY_AUDIT_HTTP_NEW_NOTIFY, //AK7 audit http
    NL_POLICY_AUDIT_FACCESS_NOTIFY, //AK6测评文件访问控制通知(8.0.5.0600)
    //审计TLS报文消息通知
    NL_POLICY_AUDIT_TLS_NOTIFY,
    //审计CLIENT_KEY_EXCHANGE请求，需要用户态同步回复
    NL_POLICY_AUDIT_TLS_REQUEST,

    NL_POLICY_AUDIT_NFCON_NOTIFY_V2, //网络连接审计v2版本通知
    NL_POLICY_AUDIT_PORTSCAN_NOTIFY_V2, //端口扫描v2版本通知
    NL_POLICY_AUDIT_FILEDEFEND_NOTIFY, //8.0.5.5150版本加入,针对工行poc
    NL_POLICY_AUDIT_PFLOW_NOTIFY_V2, //进程流量审计v2版本通知
    NL_POLICY_AUDIT_UDISK_NOTIFY_V2, //U盘审计v2版本通知
    NL_POLICY_AUDIT_NFCON_NOTIFY_SECKIT, //网络连接审计,安全套件10.0.8.1000加入
    NL_POLICY_AUDIT_SOFT_MANAGER,        //软件管家,10.8.0.1000加入
    NL_POLICY_AUDIT_FILE_NOTIFY_V2,      //驱动上报文件属组,10.8.0.1000加入
    NL_POLICY_AUDIT_NOTIFY_MAX = 0x990,

    //多网切换内核向用户态发送的通知:2448-2457
    //多网切换TLS报文消息通知
    NL_POLICY_NC_TLS_NOTIFY = 0x991,
    //多网切换CLIENT_KEY_EXCHANGE请求，需要用户态同步回复
    NL_POLICY_NC_TLS_REQUEST,
    NL_POLICY_NC_LOG_EVENT,
    NL_POLICY_NC_NOTIFY_MAX = 0x999,

    //移动存储内核向用户态发送的通知:2458-2467
    NL_POLICY_MSTORAGE_NOTIFY = 0x99A,
    NL_POLICY_MSTORAGE_PROBE,
    NL_POLICY_MSTORAGE_MOUNT, //移动存储设备mount通知
    NL_POLICY_MSTORAGE_NOTIFY_MAX = 0x9A4,

    NL_POLICY_DEVCTL_NEW_QUERY = 0x9A5,

    NL_MAX_INDEX = 0x1000, //4096
} NLPolicyType;

#define BIT_INDEX_OFFSET 8

#define ECHO_CMD_STR_SET_PORT_ID  "set portid"
#define ECHO_CMD_STR_CLEAR_PORT_ID  "clear portid"
#define ECHO_CMD_STR_ECHO     "echo"

#define ECHO_CMD_STR_SET_DEBUG     "set debug"

//the bool sync information structure
struct bool_info {
    void* pwait_flag;
    int bBool;
};

/*Note:
 *端口组(无论是用户态下给内核还是内核发送给用户态时)
 *一定要是:网络字节序
 */
struct ktq_port_pair{
    uint16_t first; //first port
    uint16_t second; //second port
}__attribute__((packed));

/*Note:
 *ipv4地址组(无论是用户态下给内核还是内核发送给用户态时)
 *一定要是:网络字节序
 */
struct ktq_ipv4_pair{
    struct in_addr s_first; //first ipv4
    struct in_addr s_second; //second ipv4
}__attribute__((packed));

/*Note:
 *ipv6地址组(无论是用户态下给内核还是内核发送给用户态时)
 *一定要是:网络字节序
 */
struct ktq_ipv6_pair{
    struct in6_addr s6_first; //first ipv6
    struct in6_addr s6_second; //second ipv6
}__attribute__((packed));

/*
 *ipv4地址/port组，全部是网络字节序
 */
struct ktq_ipport_pair {
    struct in_addr in;
    u_short port;
}__attribute__((packed));

/*
 *ipv6地址/port组，全部是网络字节序
 */
struct ktq_ip6port_pair {
    struct in6_addr in6;
    u_short port;
}__attribute__((packed));

//dns协议规定域名总长度最大限制是253
#define KTQ_DNAME_MAX      253
///////////////////////////////////////////////////////////////////////////////
//Audit System

//审计版本标识
enum audit_versions {
    AUDIT_V1 = 0, //默认版本的审计，初始版本
    AUDIT_V2, //第二个版本的审计(增加了ipv6支持)
};

enum {
    AUDIT_ACTION_NONE   =    0, //无效的审计操作
    AUDIT_ACTION_OPEN   =    1,
    AUDIT_ACTION_RENAME =    2,
    AUDIT_ACTION_TRUNCATE =  3,
    AUDIT_ACTION_CHMOD   =   4,
    AUDIT_ACTION_UNLINK  =   5,
    AUDIT_ACTION_MKDIR   =   6,
    AUDIT_ACTION_RMDIR   =   7,
    AUDIT_ACTION_CHOWN   =   8,
    AUDIT_ACTION_WRITE   =   9,
    AUDIT_ACTION_PORT_BIND = 10, //端口绑定
    AUDIT_ACTION_PORT_FREE = 11, //绑定端口释放
    AUDIT_ACTION_CREATE  =   12,
};

#define PROCESS_MONITOR_EXEC 0
#define PROCESS_MONITOR_KILL 1
#define PROCESS_MONITOR_EXIT 2
#define PROCESS_MONITOR_FORK 3

#define SERVICE_MONITOR_STOP     0
#define SERVICE_MONITOR_START    1
#define SERVICE_MONITOR_RESTART  2

#define AUDIT_PORT_BIND_AUDIT   0   //端口绑定,只审计
#define AUDIT_PORT_BIND_BLOCK   1   //端口绑定阻断
#define AUDIT_PORT_BIND_FREE    2   //端口绑定释放操作

struct port_audit_info {
    int32_t pid;
    int32_t port;
    int32_t black;
    char process_name[16];
};

//针对AK7的端口绑定审计
struct new_port_audit_info {
    int32_t pid;
    int32_t port;
    u_char action; //AUDIT_ACTION_PORT_BIND,AUDIT_ACTION_PORT_FREE
    u_char mode; //AUDIT_MODE_BLACK,AUDIT_MODE_WHITE,
    u_char op; //AUDIT_OP_AUDIT,AUDIT_OP_BLOCK
    
    char process_name[16];
};

struct port_scan_info {
    __be32 src;
    __be32 dst;
    int32_t port;
};

//新版本的audit version
struct port_scan_info_v2 {
    u_short family; //AF_INET,AF_INET4
    u_short port; //网络字节序

    //网络字节序
    union {
        struct in_addr	in; 
	    struct in6_addr	in6;
    } saddr,daddr; 
};

struct arp_defense_info {
    __be32 ip;
    unsigned char mac[20];
};

struct conm_netflow_info {
    int mode;
    int up;
    int protocol;
    __be32 sip;
    __be32 sport;
    __be32 dip;
    __be32 dport;
};

//ak6之后，主审网络连接需要审计建立连接的进程名称
//为了兼容ak6之前的版本，所以定义 struct new_conm_netflow
//结构类型;ak6(2.0.0.2000)之后的版本全部采用这些结构

struct new_conm_netflow {
    int mode;
    int up;
    int protocol;
    __be32 sip;
    __be16 sport;
    __be32 dip;
    __be16 dport;
    char comm[16];
};

struct zyj_conm_netflow {
 	int mode;
   	int up;
	int protocol;
    __be32 sip;
    __be32 sport;
    __be32 dip;
    __be32 dport;
	char comm[16];
	char app_protl[8];
};

#define AUDIT_NETSRV_HTTP "HTTP"
#define AUDIT_NETSRV_FTP "FTP"
#define AUDIT_NETSRV_SMTP "SMTP"

//2.0.0.4300版本加入:
//网络连接审计v2版本，同时支持ipv4/ipv6
//可用于替换前面的new_conm_netflow与zyj_conm_netflow
struct conm_netflow_v2 {
    u_char op; //AUDIT_OP_BLOCK/AUDIT_OP_AUDIT
    u_char mode; //AUDIT_MODE_BLACK/AUDIT_MODE_WHITE
    u_char up;
    u_char protocol;
    u_char family; //AF_INET/AF_INET6
    char netsrv[8]; //根据端口识别的网络服务名称(AUDIT_NETSRV_XXX)

    //ip/端口: 网络字节序,跟以前版本不同
    //(以前版本: port主机字节序,而ip网络字节序:做法很不标准)
    union {
        struct in_addr	in; 
	    struct in6_addr	in6;
    } saddr,daddr; 

    u_short sport;
    u_short dport;
    char comm[16];
};

enum {
    CONN_NETFLOW_B = 1,  ///< byte
    CONN_NETFLOW_KB,     ///< Kbyte
    CONN_NETFLOW_MB,     ///< Mbyte
    CONN_NETFLOW_GB,     ///< Gbyte
    CONN_NETFLOW_TB,     ///< Tbyte
};
struct conn_netflow_seckit {
    u_char up;          //< 1:流出-发送 0:流入-接收
    u_char protocol;    //< 协议TCP 、UDP
    u_char family;      //< AF_INET/AF_INET6
    u_char unit;        //< CONN_NETFLOW_xx
    u_short sport;      //< 源端口
    u_short dport;      //< 目的端口
    int64_t threshold;  //< 流量阀值
    int64_t flowsize;   //< 上传、下载流量大小
    union {             //< 源IP、目的IP
        struct in_addr  in;
        struct in6_addr in6;
    } saddr, daddr;
    pid_t pid;          //< 进程id
    char comm[16];      //< 进程名
};

struct process_flow {
    char comm[16];
    int32_t pid;
    int up;
    int sock_type;
    int flowsize;
    struct sockaddr selfaddr;
    struct sockaddr peeraddr;
	int action; //for shield
};

struct process_flow_v2 {
    char comm[16];
    int32_t pid;
    int up;
    int sock_type;
    int flowsize;
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } selfaddr, peeraddr;
    int action;
};

struct process_info {
    int32_t pid;
    int32_t uid;
    int32_t ppid;
    int32_t action;
	int32_t decision;
    int64_t memsize;
    long time;
	char process_name[256];
	char process_parent[256]; //for shield
};

struct process_info_inner {
    int32_t pid;
    int32_t uid;
    int32_t ppid;
    int32_t action;
	int32_t decision;
    int64_t memsize;
    long time;
	char process_name[256];
};

struct service_info {
	int32_t pid;
	int32_t uid;
	int32_t action;
    long time;
	char server_name[32];
	char dir_name[256];
};

struct print_info {
	char job_id[16];
	char files[16]; //打印的文件份数
	char filename[64];
};

#ifdef __KERNEL__
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
			#ifndef _STRUCT_TIMESPEC
			struct timespec {
				__kernel_old_time_t tv_sec;
				long tv_nsec;
			};
			
			struct timeval {
				__kernel_long_t tv_sec;
				__kernel_long_t tv_usec;
			};
			#endif
	#endif
#endif

struct path_info {
	char path[256];
	unsigned short mode;
	int32_t uid;
	struct timespec i_atime;
	struct timespec i_mtime;
	struct timespec i_ctime;
};

struct file_op_monitor {
    struct process_info_inner pi;
    struct path_info src_path;
    struct path_info dst_path;
	int hit;
};

//NL_POLICY_AUDIT_FILEDEFEND_NOTIFY
struct path_info_v2 {
    struct path_info path;
	unsigned short op;
};

struct file_op_monitor_v2 {
    struct process_info_inner pi;
    struct path_info_v2 src_path;
    struct path_info_v2 dst_path;
	int hit;
};
////

////////// 10.8.0.1000 chown需上报属组,故修改
//上报类型: NL_POLICY_AUDIT_FILE_NOTIFY_V2
typedef struct {
    unsigned short mode;
    unsigned short op;
    int32_t uid;
    int32_t gid;
    struct timespec i_atime;
    struct timespec i_mtime;
    struct timespec i_ctime;
    char path[256];
} path_info_t;

typedef struct {
    int hit;
    struct process_info_inner pi;
    path_info_t src_path;
    path_info_t dst_path;
} file_op_monitor_t;
//////////

struct kill_notify_data {
    int32_t source_pid;
    int32_t target_pid;
    int32_t sig;
    int32_t source_uid;
    int32_t target_uid;
};

struct file_access_notify_data{
    struct process_info_inner pi;
    int32_t flag;
};

struct flow_monitor_notify_data {
	long long flowthreshold;
	long long overload;
	long timeinterval;
	int action;
	int direction;
};


struct flow_monitor_audit_data {
	char process_name[20];
	long long upflow;
	long long downflow;
	long long total_flow;	
};

struct flow_monitor_audit_info {
	int count;
	struct flow_monitor_audit_data entry[0];
};

struct http_info {
	int type;
	int host_len;
	char pname[128];
	char host[0];
};

//AK7针对http协议审计的类型
struct new_http_info {
    u_char mode; //AUDIT_MODE_WHITE/AUDIT_MODE_BLACK
    u_char op; //AUDIT_OP_AUDIT/AUDIT_OP_BLOCK
	int host_len;
	char comm[16]; //进程名长度最长15个字节
	char host[0];
};

struct udisk_audit_info { // for shield
	int32_t pid;
	int32_t uid;
	int32_t action;
	char path[256];
	char comm[16];	
    long time;
};

/* 4300之后审计版本为v2时U盘审计上报日志 */
struct udisk_audit_info_v2 {
    int32_t pid;
    int32_t uid;
    int32_t action;
    char src_path[256];
    char dst_path[256];
    char comm[16];
    long time;
};

//针对AK6测评加的,文件访问控制通知
//用户态返回给内核的结构是struct bool_info*
//用于通知内核允许/禁止本次文件访问操作
typedef struct audit_faccess_s {
	u_char action; //AUDIT_ACTION_OPEN,AUDIT_ACTION_WRITE,AUDIT_ACTION_RENAME
    int32_t pid;
    int32_t uid;
	char comm[16];
    void* pwait_flag;
    u_short pathlen; //文件路径长度，用于标识path的长度
	char path[0]; //非固定长度，长度由pathlen标识，并且不是以\0结尾的字符串
} audit_faccess_t;

enum {
    MNT_ACTION_MOUNT = 1,
    MNT_ACTION_UMOUNT = 2,
};

struct dev_mount_info {
    char mnt_path[256]; //挂载路径
    char dev_name[128];    //设备名称
    char pname[16]; //操作进程名称
    int action;  //事件动作，1 挂载  2 卸载
};

struct mstorage_dev_mnt {
    char mnt_path[256]; //挂载路径
    char dev_name[128];    //设备名称
    int pid;
    void* pwait_flag;
};
////////////////////////////////////////////////////////////////////////////////
//Security Document

#define PROCESS_MONITOR_EXEC 0
#define PROCESS_MONITOR_KILL 1
#define PROCESS_MONITOR_EXIT 2

#define DOCUMENT_PRINT -360360
#define DOCUMENT_COPY  -1361361
#define DOCUMENT_PASTE -2362362

#define Q_NORDWR 0
#define Q_RDONLY 1
#define Q_WRONLY 2
#define Q_RDWR   3

// open file information to user
struct sec_label_open_info {
    int pid;
    int uid;
    void* pwait_flag;
    char comm[16];
    char path[1024];
};

struct sec_label_unlink_file {
    int pid;
    void* pwait_flag;
    char path[1024];
};

struct sec_label_redirect_file {
    int id;
    void* pwait_flag;
    int mode;
    char path[1024];
};

struct sec_label_task_exit_info {
    int pid;
    int uid;
    int restored;
    void* pwait_flag;
};

struct sec_label_oper_info{
    int pid;
    int oper_id;
    void* pwait_flag;
};

struct sec_label_close_info {
    int id;
    int pid;
    int bwrite;
    void* pwait_flag;
    int uid;//euid
    char path[1024];
    char comm[16];
};

struct sec_label_rename_info {
    int pid;
    char comm[16];
    char src_path[1024];
    char dst_path[1024];
    void* pwait_flag;
    int uid; //euid
};

struct sec_label_cp_info {
    int pid;
    char comm[16];
    char src_path[1024];
    char dst_path[1024];
    int rc;
};

struct sec_label_scr_oper {
    u_char scr_rec_on;
    u_char scr_shot_on;
};

struct sec_label_scr_info {
    u_char scr_type;     // 0 - 截屏 1 - 录屏
    u_char scr_oper_ret; // 0 - 成功执行 1 - 禁止执行
    long __fill_size;    // 扩充结构体，CONFIG_DEBUG_VM
};

struct sec_label_policy_opt {
    u_char enabled;  // 重定向opt 0 - 不启用 1 - 启用
    char path[1024]; // 需要重定向的路径
};

struct sec_label_policy_redirect {
    char path_home[1024];  // home path
    char path_mount[1024]; // 重定向mount点
};

////////////////////////////////////////////////////////////////////////////////
//network changed
struct network_dns_name {
    char domain[256];
    void* pwait_flag;
};

struct network_dns_ip {
    int ips[10];
    void* pwait_flag;
};

struct nc_tls_ip {
    u_int ips[10];
};
//多网切换TLS协议通知
typedef struct nc_tls_notify {
    uint16_t len;
    void* pwait_flag;
    u_char data[0];
}nc_tls_notify_t;

typedef nc_tls_notify_t audit_tls_notify_t;

struct sec_label_rename_specarch_info {
    int pid;
    char comm[16];
    char src_path[1024];
    char dst_path[1024];
    char cmdline[2048];
    void* pwait_flag;
    int uid; //euid
};


///////////////////////////////////////////////////////////////////////////////
//防护级别
enum {
    AV_HIGH_LEVEL = 1, //高级防护: 监控文件写入及程序执行
    AV_LOW_LEVEL  = 2, //低级别;监控程序执行
};
// open file information to user
typedef enum {
    ACTION_WRITE_FILE,
    ACTION_RENAME,
    ACTION_BOOT,
    ACTION_LOADLIB,
 //   ACTION_INOTIFY = 0,
    ACTION_INOTIFY,
} FILE_AUDIT_ACTION;

typedef struct {
    pid_t pid;
    FILE_AUDIT_ACTION action;
    char filepath[1024];
    char comm[16];
    char org_path[1024];
    int dpkg_rpm_flag;
} KFILE_INFO;



enum {
    AV_EXEC_NONE = -1,//初始化值(用户态及内核之间交互时不应该返回该值)
    AV_EXEC_OK = 0, //白文件允许运行
    AV_EXEC_DENY = 1, //禁止运行
    AV_EXEC_VIRUS = 0x2, //是病毒
};

//忽略进程运行病毒不处理，直接允许
#define AV_EXEC_IGNORE (AV_EXEC_OK | AV_EXEC_VIRUS)
#define AV_EXEC_ALLVALS (AV_EXEC_VIRUS | AV_EXEC_DENY | AV_EXEC_OK)

struct av_process_info {
    int pid;
    int ppid;
    int uid;
    void* pwait_flag;
    char comm[16];
    char comm_p[16];
    //char dst_path[1024];
    int type;
    int is_dir:3,
        deny:3,
        param_pos:10,
        is_monitor_mode:2;
    char path[1024];
};

//utimes/futimes调用通知
//针对普通文件的utimes调用通知
//其实我们此处主要关心的是mtime与path
struct av_utimes_info {
    int pid;
    long mtime; //utimes调用成功后的最后修改时间
    char comm[16];
    char path[1024]; //文件路径
};

struct symbol_msg {
	long sym_addr;
	char name[0];
};

struct mstorage_probe_info {
	char serial[64];
    void* pwait_flag;
};

struct dev_ctrl_info {
    int pid;
    int uid;
    int deny;
    void* pwait_flag;
    char comm[16];
    char dev[1024];
    char path[1024];
};

////////////////////////////////////////////////////////////////
/*TLV通信格式
* |--1 Byte Product-Type标识--|--2Byte Fields长度标识(主机字节序)--|---Fields----|
* Fields格式也是TLV，其具体格式由各个产品功能模块来决定;Fields可以有多个Field组成
* 每个Field其格式如下
* |--1 byte Value-Type标识---|--2Byte Value长度标识--|--Value------|
*/

 //TLV通信格式的 Value-Type,VT is a short-name for Value-Type
 enum {
    TLV_VT_PID = 1, //进程PID,Value对应数据类型为UINT
    TLV_VT_OPATH,//原始文件路径，Value对应数据类型为Str，此处不是以\0结束的C-Str
    //我们将TLV_VT_PATH定义为TLV_VT_OPATH，
    //方便后续只上报一个路径的情况，并且可能省下一个枚举定义
    #define TLV_VT_PATH TLV_VT_OPATH 
    TLV_VT_OMODE,//原始文件权限,Value对应数据类型为UINT
    TLV_VT_OUID,//文件原始用户UID,Value对应数据类型为UINT
    TLV_VT_OGID,//文件原始用户GID，Value对应数据类型为UINT
    TLV_VT_OCTIME,//文件原始创建时间，Value对应数据类型为UINT64
    TLV_VT_OMTIME,//文件原始最近一次修改时间，Value对应数据类型为UINT64
    TLV_VT_OSIZE,//原始文件大小,Value对应数据类型为UINT64
    TLV_VT_ATIME,//最后访问时间，不区分新旧，Value对应数据类型为UINT64
    TLV_VT_NPATH,//新文件路径，Value对应数据类型为Str，此处不是以\0结束的C-Str
    TLV_VT_NMODE,//新的文件权限,Value对应数据类型为UINT
    TLV_VT_NUID,//文件新的UID,Value对应数据类型为UINT
    TLV_VT_NGID,//文件新的GID,Value对应的数据类型为UINT
    TLV_VT_NCTIME,//文件新的创建时间，Value对应数据类型为UINT64
    TLV_VT_NMTIME,//文件新的最近一次修改时间，Value对应数据类型为UINT64
    TLV_VT_NSIZE,//新的文件大小,Value对应数据类型为UINT64
    TLV_VT_MUID,//文件最后一次修改的用户ID,Value对应数据类型为UINT
    TLV_VT_RUID,//real uid,Value对应数据类型为UINT
    TLV_VT_EUID,//effective uid,Value对应数据类型为UINT
    TLV_VT_RGID,//real gid,Value对应数据类型为UINT
    TLV_VT_EGID,//effective gid,Value对应数据类型为UINT
    TLV_VT_TSID,//task session-id,Value对应数据类型为UINT
    TLV_VT_PPID,//task parent pid,Value对应数据类型为UINT
    TLV_VT_COMM,//进程名，Value类型为Str，最长为15个字符
    TLV_VT_CMDLINE,//进程执行时的命令行参数
    TLV_VT_PCMDLINE,//进程的直属父进程的命令行参数
    TLV_VT_TASKENV,//进程环境变量，Value对应数据类型为Str，此处不是以\0结束的C-Str
    TLV_VT_TIMESTAMP,//时间,Value对应数据类型为UINT64
    TLV_VT_PCOMM,//父进程名,Value类型为Str，最长为15个字符
    TLV_VT_SWITCH = 30, //开关标识，Value类型为uchar
    TLV_VT_WAITKEY = 31,//内核挂起等待标识,Value类型为UINT64
    TLV_VT_OP,//通用operation值,Value类型为UCHAR
    TLV_VT_FLAG,//通用flag值,Value类型为UINT
    TLV_VT_ADGID,//主防规则GID,Value类型为USHORT
    TLV_VT_ADRID,//主防规则ID,Value类型为USHORT
    TLV_VT_ADACT,//主防action值,Value类型为UINT
    #define TLV_VT_ADOP TLV_VT_OP //主防op值
    #define TLV_VT_ADFLAG TLV_VT_FLAG//主防flag值
    TLV_VT_KONAME,//内核模块名,Value类型为Str，不是以\0结尾的C-STR
    TLV_VT_SRCVER,//驱动文件SRCVER,Value类型为Str，不是以\0结尾的C-STR
    TLV_VT_BINMD5,//二进制md5串,长度为16字节,Value类型为Str，不是以\0结尾的C-STR
    TLV_VT_FD,//文件句柄fd值,Value类型为UINT
    TLV_VT_MAXFD,//文件句柄fd限制值,Value类型为UINT

    TLV_VT_ID,//通用ID标识，Value类型为UINT
    TLV_VT_IPPROTO, //通用ip协议标识,Value类型为UCHAR
    TLV_VT_STR,//通用Str类型,Value类型为STR，不是以\0结尾的C-STR

    TLV_VT_SIPV4,//源IPV4地址，网络字节序，Value类型为UNINT
    TLV_VT_DIPV4,//目标IPV4地址，网络字节序，Value类型为UINT
    TLV_VT_SPORT,//源端口，主机字节序,Value类型为USHORT
    TLV_VT_DPORT,//目标端口，主机字节序,Value类型为USHORT
    TLV_VT_SDEVADDR,//源设备地址，Value类型Str，不是以\0结尾的C-STR
    TLV_VT_DDEVADDR,//目地设备地址，Value类型Str,不是以\0结尾的C-STR

    TLV_VT_FWINIF, //流入接口名称,Value类型为Str，不是以\0结尾的C-STR
    TLV_VT_FWOUTIF,//流出接口名称，Value类型为Str,不是以\0结尾的C-STR
    TLV_VT_FWLOGALL,//防火墙日志全部上报标识，Value类型为UCHAR,0-->只上报拦截的报文,1-->上报所有匹配规则的报文(包括拦截与允许)
    TLV_VT_FWSKIPLOOPBACK,//loopback接口上的报文过滤标识，Value类型为UCHAR,0-->过滤,1-->放过

    TLV_VT_SIPV6,//源IPV6地址,网络字节序，Value类型为UCHAR[16](固定16字节,对应struct in6_addr.s6_addr)
    TLV_VT_DIPV6,//目标IPV6地址,网络字节序，Value类型为UCHAR[16](固定16字节,对应struct in6_addr.s6_addr)
    TLV_VT_DNAME,//域名,Value类型为Str,不是以\0结尾的C-STR
    TLV_VT_VARIANT,//变长数据类型，Value类型为二进制串(由使用者自行解释其含义)
    TLV_VT_NETDIRECT,//网络流向标识,Value类型为UCHAR
    TLV_VT_MODE,//统一模式标识，Value类型为UCHAR
    TLV_VT_PORTPAIR,//端口组,Value类型为struct ktq_port_pair
    TLV_VT_IPV4PAIR,//ipv4组,Value类型为struct ktq_ipv4_pair
    TLV_VT_IPV6PAIR,//ipv6组,Value类型为struct ktq_ipv6_pair
    TLV_VT_VER,//版本标识,Value类型为UCHAR
    TLV_VT_IPPORTPAIR,//ipv4/port组，Value类型为(struct ktq_ipport_pair)
    TLV_VT_IP6PORTPAIR,//ipv6/port组，Value类型为(struct ktq_ip6port_pair)
    TLV_VT_TYPE,//通用类型标识，Value类型为UINT
    #define TLV_VT_FWDNAME TLV_VT_DNAME //防火墙域名，url防火墙匹配成功后上报的日志中使用该字段
    #define TLV_VT_FWGID TLV_VT_TYPE //防火墙模块ID,Value类型为UINT
    #define TLV_VT_FWRID TLV_VT_ID //防火墙规则ID,Value类型为UINT
    #define TLV_VT_FWNFRC TLV_VT_OP //防火墙报文处理结果值，FW_NF_ACCEPT(0)-->accept,FW_NF_DROP(1)-->drop,Value类型为UCHAR
    #define TLV_VT_FWCMDEXEOP TLV_VT_OP //防火墙命令程序指令操作标识,FW_CMDEXE_CLEAN-->清理,FW_CMDEXE_ADD-->添加
    #define TLV_VT_FWCMDEXE TLV_VT_STR //防火墙命令程序完整路径

    #define TLV_VT_AVFE TLV_VT_OP    //杀毒文件事件类型(AV_FE_XXX)
    #define TLV_VT_AVFT TLV_VT_FLAG //杀毒文件事件中的文件类型(可选值在下面AV_FT_XXX)

    #define TLV_VT_IPV4 TLV_VT_SIPV4 //通用IPV4地址
    #define TLV_VT_IPV6 TLV_VT_SIPV6 //通用IPV6地址

    #define TLV_VT_AUDITMODE TLV_VT_MODE //审计匹配模式,可选值AUDIT_MODE_XXX

    #define TLV_VT_NCMODE TLV_VT_MODE //多网切换匹配模式
    #define TLV_VT_NCDNAME TLV_VT_DNAME
    #define TLV_VT_NCPROTO TLV_VT_IPPROTO //多网切换协议匹配标识

    #define TLV_VT_DNSRC    TLV_VT_MODE //edr rcode值
    #define TLV_VT_DNSTYPE  TLV_VT_TYPE //dns查询类型
    #define TLV_VT_DNSLOGTYPE TLV_VT_FLAG //DNS日志类型(DNS_LOG_TYPE)
    #define TLV_VT_NETDETMODE TLV_VT_MODE  //违规外联管控标识
    #define TLV_VT_AVDEBRPM  TLV_VT_TYPE  //实时防护同步事件dpkg/rpm安装(AV_EXEC_FILE,AV_EXEC_DEBRPM)
    #define TLV_VT_FILEFIRM_ACT TLV_VT_ADACT  //文件加固的act
    #define TLV_VT_EDR_UDISKACT TLV_VT_ADACT  //edr的u盘审计action
    #define TLV_VT_DEFENSE_ACT  TLV_VT_ADACT  //自保的act
 };


//TLV数据的最小长度
#define TLV_DATA_LEN_MIN   4
#define TLV_DATA_LEN_MAX   0xFFFF

//1 Byte Product-Type,2 Bytes Fileds length
//the header length of tlv 
#define TLV_HDR_LEN      3
//兼容2.0.0.4000之前的版本
#define TLV_HEADER_LEN   TLV_HDR_LEN

typedef struct ktq_tlv_hdr {
    u_char pt;
    u_short len;
    u_char fields[0];
} __attribute__((packed)) ktq_tlv_hdr_t;

//TLV通信协议格式的Product-Type
enum {
    TQ_PT_NONE = 0,
    TQ_PT_CORE = 1,
    TQ_PT_SELF, //自保
    TQ_PT_AV, //杀毒
    TQ_PT_APP_CONTROL, //应用控制(目前无用)
    TQ_PT_AUDIT, //审计
    TQ_PT_LABEL, //密标
    TQ_PT_DEV_CTRL, //设备控制
    TQ_PT_NAC_WATER, //水印
    TQ_PT_NC, //多网切换
    TQ_PT_DEV, //外设(不是管控类的，用于外设接入通知)
    TQ_PT_NETDETECT,//违规外连(8.0.5.1200)
    TQ_PT_AD,//主防(8.0.5.1300)
    TQ_PT_FW,//防火墙(8.0.5.1300)
    TQ_PT_EDR,//EDR(8.0.5.5100)
    TQ_PT_FILEFIRM,  //文件加固(工控二期)
    TQ_PT_SOFTWARE,//软件管家(10.7.0.1000)
    TQ_PT_KERNEL,  // base libEntKernel.so 全局加白防火墙使用
    TQ_PT_SC,  // 安检合规（10.8.0.1000）
    TQ_PT_MAX = 0xFF,
};

//网络流向标识
#define KTQ_NET_IN 0 //注入
#define KTQ_NET_OUT 1 //流出

/*
 *Core指令(用户态发给内核的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_CORE)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_CORE其Fields，格式如下:
 *|--1 Byte CORE_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum CORE_CMD_TYPE {
     /*
     *下发控制中心ip地址信息指令
     *其Data格式如下:
     *IPV4地址(TLV_VT_IPV4,可能没有)
     *IPV6地址(TLV_VT_IPV6，可能没有)
     *Note: IPV4,IPV6地址不允许同时没有
     */
    CORE_CMD_CCIP = 1, //下发控制中心ip信息指令
};

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 *审计指令策略(用户态发给内核的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_AUDIT)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_AV其Fields，格式如下:
 *|--1 Byte AUDIT_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
//审计TLV策略类型
enum AUDIT_CMD_TYPE {
    AUDIT_CMD_WBRL_NETPORT  = 1, //网络端口监听审计
    AUDIT_CMD_WBRL_NETCONN, //网络连接
    AUDIT_CMD_WBRL_TASK, //进程监控
    AUDIT_CMD_WBRL_HTTP, //HTTP协议监控
    AUDIT_CMD_WBRL_NEWNETCONN,//新的网络连接策略(2.0.0.4200版本的驱动中新加，用于代替换原AUDIT_CMD_WBRL_NETCONN格式)

    /*
     *网络连接V2策略(2.0.0.4300版本的驱动中新加，采用标准TLV格式,同时支持ipv4/ipv6)
     *
     *其Data格式如下:
     *审计模式(对应字段类型为TLV_VT_AUDITMODE,对应值: AUDIT_MODE_XXX)
     *审计操作类型(对应字段类型为TLV_VT_OP,对应值:AUDIT_OP_XX)
     *五元组数据(TLV_VT_VARIANT,可以有多个),该五元组的数据仍然是TLV(方便后续增加字段)，其字段如下:
     *  >协议标识(TLV_VT_IPPROTO)
     *  >IPV4目地地址(TLV_VT_DIPV4,可能没有,可能为INADDR_ANY)
     *  >IPV6目地地址(TLV_VT_DIPV6,可能没有,也可能为IN6ADDR_ANY)
     *  >源端口(TLV_VT_SPORT),目地端口(TLV_VT_DPORT)
     *  >流向(TLV_VT_NETDIRECT,对应值AUDIT_NET_XX)
     */
    AUDIT_CMD_WBRL_NETCONNV2,
    /*
     *版本设置指令:
     *其Data格式如下:
     * 版本信息(TLV_VT_VER,可选值AUDIT_VX)
     */
    AUDIT_CMD_VER,
    AUDIT_CMD_WBRL_FILEDEFEND,//工行POC
    /*
     *服务器地址ip(TLV_VT_IPV4/TLV_VT_IPV6)
     *可同时支持ipv4/ipv6
     */
    AUDIT_CMD_SERVIP,
    //新版本http协议监控(v10.3.0.5000版本引入的，对应驱动是2.0.0.4520,支持http白名单内审计)
    //格式与AUDIT_CMD_WBRL_HTTP的相同，内核只是需要用这个新的CMD-TYPE来区分新旧策略!!
    AUDIT_CMD_NEW_WBRL_HTTP,
    AUDIT_CMD_MAX = 0xFF,

    //下面的是为了兼容(2.0.0.4300之前的版本专门定义的宏)
    #define AUDIT_TYPE_WBRL_NETPORT AUDIT_CMD_WBRL_NETPORT 
    #define AUDIT_TYPE_WBRL_NETCONN  AUDIT_CMD_WBRL_NETCONN 
    #define AUDIT_TYPE_WBRL_TASK AUDIT_CMD_WBRL_TASK 
    #define AUDIT_TYPE_WBRL_HTTP AUDIT_CMD_WBRL_HTTP
    #define AUDIT_TYPE_WBRL_NEWNETCONN AUDIT_CMD_WBRL_NEWNETCONN
    #define AUDIT_TYPE_MAX AUDIT_CMD_MAX
};

//审计操作类型
enum {
    AUDIT_OP_AUDIT = 0, //只审计
    AUDIT_OP_BLOCK = 1, //阻断
    AUDIT_OP_NONE = 0xFF, //什么也不做,策略中不会下发这个值，这个是程序内部使用的
};

//审计名单模式
enum {
    AUDIT_MODE_WHITE = 0,//白名单模式
    AUDIT_MODE_BLACK = 1,//黑单模式
    AUDIT_MODE_RED = 2,//红单模式
    AUDIT_MODE_NONE = 0xFF,//无效的模式，该状态时不用做任何操作
};

//审计策略网络流向
enum {
	AUDIT_NET_NIL = 0, //没有设置流向,出现此值绝对不会匹配
	AUDIT_NET_IN = 1, //流入
	AUDIT_NET_OUT = 2, //流出
	AUDIT_NET_ALL = 3, //任意
};
///////////////////////////////////////////////////////////////////////////////////////////

/*
 *违规外边的TLV指令(用户态发给内核的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_NETDET)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_NETDET其Fields，格式如下:
 *|--1 Byte NETDET_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum NETDET_CMD_TYPE {
    NETDET_CMD_SWITCH = 0,//开关
    NETDET_CMD_WHITE_IPS,//加白ip列表
    NETDET_CMD_NETCARD_CTL,// 网卡管控

    /*
     *加白ip列表v2版本(2.0.0.4300版本引入，同时支持ipv4/ipv6)
     *其Data格式如下:
     *IPPORT/IP6PORT组(TLV_VT_IPPORTPAIR/TLV_VT_IP6PORTPAIR,可以有多个，也可以同时有ipv4/ipv6)
     */
    NETDET_CMD_WHITE_IPSV2,
    NETDET_CMD_IP4IP6_CTL,
    NETDET_CMD_MAX = 0xFF,

    //兼容2.0.0.4300之前的版本定义成宏
    #define NETDET_TYPE_SWITCH  NETDET_CMD_SWITCH
    #define NETDET_TYPE_WHITE_IPS NETDET_CMD_WHITE_IPS
    #define NETDET_TYPE_NETCARD_CTL NETDET_CMD_NETCARD_CTL
    #define NETDET_TYPE_MAX  NETDET_CMD_MAX
};

//违规外联网卡管控标识:
enum {
    NETDET_NCDCTL_NOP = 0x00,//全部关闭
    NETDET_NCDCTL_IP = 0x01,//ipv4地址
    NETDET_NCDCTL_IP6 = 0x02,//ipv6地址
    NETDET_NCDCTL_MAC = 0x04,//MAC地址
    NETDET_NCDCTL_ROUTE = 0x08,//路由
    NETDET_NCDCTL_NETMASK = 0x10,//netmask
    NETDET_NCDCTL_ALL = 0x1F,
};

//违规外联管控标识：
enum {
    NETDET_CTL_IP4IP6 = 0,        //管控ipv4ipv6
    NETDET_CTL_IP4 = 1,           //只管控ipv4
    NETDET_CTL_IP6 = 2,           //只管控ipv6
};
///////////////////////////////////////////////////////////////////////////////////////////

/*设备事件类型,该事件对应的产品类型是TQ_PT_DEV
 *报文格式:
 *|--1 Byte product-type(TQ_PT_DEV)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_DEV其Fields只有一个，格式如下:
 *|--1 Byte DEV_EVENT_TYPE-|--Data--|
 */

//DEV_EVENT_TYPE的可选值如下：
enum {
    DEV_EVENT_NET = 0,//网络设备事件
    DEV_EVENT_USB = 1,//usb设备事件
};

//DEV_EVENT_NET网络设备事件的Data
//Note: 这里的值必须与内核中的NETDEV_XXX值一一对应且相同
//这个是必须的，因为内核的NETDEV_XXX值不对用户态程序公开
enum {
    NETDEV_EVENT_UP = 0x0001,
    NETDEV_EVENT_DOWN = 0x0002,
    NETDEV_EVENT_CHANGE	= 0x0004,	/* Notify device state change */
    NETDEV_EVENT_REGISTER = 0x0005,
    NETDEV_EVENT_UNREGISTER	= 0x0006,
    NETDEV_EVENT_CHANGEMTU = 0x0007,
    NETDEV_EVENT_CHANGEADDR	= 0x0008,
    NETDEV_EVENT_CHANGENAME	= 0x000A
};
//DEV_EVENT_NET的Data类型如下
typedef struct tq_netdev_ifi_s {
    u_int               event; //NETDEV_EVENT_XXX
    char	            name[16];
    int                 ifindex;
    u_int               flags; //IFF_XXX defined in net/if.h
    u_int		        mtu;
    struct sockaddr     addr; //may be waste a port value
    u_char              hwaddr[6]; //binary-mac
}tq_netdev_ifi_t;

///////////////////////////////////////////////////////////////////////////////////////////////////////
enum {
    AV_FE_ACCESS = 1, //常规文件访问事件(针对普通文件是write-close)
    AV_FE_TRACESRC, //cp/mv的文件溯源事件
    AV_FE_FMGRREADDIR,//文件管理器读取目录(文件管理器在实际访问目录时会触发该事件)
    AV_FE_ARCHIVEDIR, //归档管理器重命名目录 (归档管理器，像engrampa解压时将文件放到一个临时目录，然后将整个目录重命名成目地目录)
};

//杀毒触发文件事件的文件类型(file-type)
enum {
    AV_FT_FILE = 1, //文件
    AV_FT_DIR = 2, //目录
};

//实时防护dpkg/rpm同步事件压缩包扫描
enum {
    AV_EXEC_FILE = 1, //文件
    AV_EXEC_DEBRPM = 2, //DEB/RPM压缩包
};

/*
 *杀毒进程启动事件通知(内核发给用户态的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_AV)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_AV其Fields，格式如下:
 *|--1 Byte AV_EVENT_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */

//AV_EVENT_TYPE的可选值如下
enum {
     /*
     *杀毒进程启动事件,此处全部使用原始文件相关值Data包含:
     *进程PID，进程名(TVL_VT_COMM),进程可执行文件路径(TLV_VT_PATH),
     *进程real-uid,进程effective-uid,进程real-gid,进程effective-gid
     *内核等待标识(TLV_VT_WAITKEY)
     *下面几个字段在现阶段是关闭的
     *父进程ID
     *父进程可执行文件路径(TLV_VT_NPATH),
     *进程命令行参数(TLV_VT_CMDLINE),父进程命令行参数(TLV_VT_PCMDLINE)
     *进程环境变量(TLV_VT_TASKENV)
     */
    AV_EVENT_EXEC = 1,//进程启动
    /*
     *杀毒文件事件,此处全部使用原始文件相关值Data包含:
     *进程PID，进程名(TVL_VT_COMM),
     *进程real-uid,进程effective-uid
     *文件事件类型(TLV_VT_AVFE)
     *文件类型(TLV_VT_AVFT)
     *文件路径(TLV_VT_PATH,该值一定会有，针对文件事件为AV_FE_ACCESS时就是触发事件的路径，对于TLV_FE_CPMV则为源路径)
     *文件目地路径(TLV_VT_NPATH,该字段只有在文件事件为TLV_FE_CPMV时才有)
     */
    AV_EVENT_FILE = 2,//文件事件

     /*
     *杀毒进程启动参数检查事件,此处全部使用原始文件相关值Data包含:
     *进程PID，进程名(TVL_VT_COMM),参数中文件路径(TLV_VT_PATH),
     *进程real-uid,进程effective-uid,进程real-gid,进程effective-gid
     *内核等待标识(TLV_VT_WAITKEY),
     *该事件对应的文件类型(TLV_VT_AVDEBRPM,8.0.5.5149版本新加的)
     */
    AV_EVENT_EXECARG = 3,//进程启动参数检查事件

    /*
     *AV SO加载事件通知(2023.04.21 工控IEP加入)
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *SO文件路径(TLV_VT_PATH),
     *父进程ID
    */
    AV_EVENT_LOADSO = 4,
};

/*
 *杀毒指令(用户态发给内核的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_AV)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_AV其Fields，格式如下:
 *|--1 Byte AV_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum AV_CMD_TYPE {
    /*
     *杀毒开关指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    AV_CMD_SWITCH = 1,

    /*
     *AV加载so开关指令(工控项目 2023.04.24加入)
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
    */
    AV_CMD_SO = 2,
};
//////////////////////////////////////////////////////////////////////////////////////////////////////

//兼容之前自保的act
enum DEFENSE_ACT{
    DEF_ACT_NONE   = 0,
    //文件act
    DEF_ACT_CREATE = 7,  //创建文件
    DEF_ACT_FILE   = 8,  //修改文件
    DEF_ACT_RENAME = 9,  //重命名
    DEF_ACT_UNLINK = 10, //删除文件
    DEF_ACT_MKDIR  = 11, //创建目录
    DEF_ACT_LINK   = 12, //创建软链
    DEF_ACT_OPEN   = 13, //独占打开
    DEF_ACT_WRITE  = 14, //修改内容
    DEF_ACT_CHOWN  = 15, //修改属性
    DEF_ACT_CHOMD  = 16, //修改权限
};

/*
 * 自保事件通知(内核发给用户态的)
 * 报文格式:
 * |--1 Byte product-type(TQ_PT_SELF)--|--2Byte length--|--Fields--|
 * Fields可以有多个;但对于TQ_PT_SELF其Fields，格式如下:
 * |--1 Byte DEFENSE_EVENT_TYPE-|--2 byte Data-Length--|--Data--|
 * Data也是由多个TLV格式的不同值组成
 */
//DEFENSE_EVENT_TYPE的可选值如下
enum {
    /*
     * 自保文件事件,此处全部使用原始文件相关值Data包含:
     * 进程PID，进程名(TVL_VT_COMM),
     * 进程real-uid,进程effective-uid
     * 文件事件类型(TLV_VT_AVFE)
     * 文件类型(TLV_VT_AVFT)
     * 文件路径(TLV_VT_PATH,该值一定会有，针对文件事件为AV_FE_ACCESS时就是触发事件的路径，对于TLV_FE_CPMV则为源路径)
     * 文件目地路径(TLV_VT_NPATH,该字段只有在文件事件为TLV_FE_CPMV时才有)
     */
    DEFENSE_EVENT_LOG = 1, //文件事件
};

enum {
    NC_MODE_BLACK = 0,//黑名单
    NC_MODE_WHITE = 1,//白名单
    NC_MODE_MAX = 0xFF,
};

//多网切换域名匹配方式
enum NC_DNAME_MTYPE {
    NC_DNAME_MFULL = 0, //全词匹配(www.baidu.com)
    NC_DNAME_MPRE  = 1, //前向模糊匹配(www.baidu.*)
    NC_DNAME_MMENT  = 2, //后向模糊匹配(*.baidu.com)
    NC_DNAME_MPREMENT  = 3,//前后项模糊匹配(*.baidu.*)
};

//多网切换规则协议匹配标识
enum {
    NC_PROTO_NIL = 0, //无效值，规则匹配时如果是些值则不考虑协议匹配
    NC_PROTO_TCP = 1, //tcp
    NC_PROTO_UDP = 2, //udp
    NC_PROTO_TCPUDP = 3, //同时匹配tcp/udp
};

//多网切换版本标识
enum nc_versions {
    NC_V1 = 0, //默认版本的多网切换，初始版本
    NC_V2, //第二个版本的多网切换(增加了ipv6支持)
};

/*多网切换指令(用户态下发给内核的),对应的产品类型是TQ_PT_NC
 *报文格式:
 *|--1 Byte product-type(TQ_PT_NC)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_NC其Fields只有一个，格式如下:
 *|--1 Byte NC_CMD_TYPE-|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
//NC_CMD_TYPE的可选值如下
enum NC_CMD_TYPE {
    /*
     *版本设置指令:
     *其Data格式如下:
     * 版本信息(TLV_VT_VER,可选值NC_VX)
     */
    NC_CMD_VER = 1,
    NC_CMD_SERVERIP = 2, //server_ip
    NC_CMD_NAC_SERVERIP = 3, //nac_server_ip
    //兼容2.0.0.4300之前的旧版本
    #define NC_TYPE_SERVERIP NC_CMD_SERVERIP 
    #define NC_TYPE_NAC_SERVERIP NC_CMD_NAC_SERVERIP

    /*
     *多网切换规则下发指令(2.0.0.4300加入,之前的版本采用的旧的struct结构)
     *其Data格式如下:
     *|---匹配模式(TLV_VT_NCMODE)---|----匹配规则组(TLV_VT_VARIANT,可以有多个)----|
     *a.匹配模式(对应字段类型为TLV_VT_NCMODE,对应值: NC_MODE_XXX)
     *b.匹配规则组(TLV_VT_VARIANT,可以有多个),该规则组的数据仍然是TLV(方便后续增加字段)，其字段如下:
     *  >多网切换协议匹配标识(TLV_VT_NCPROTO,url匹配时直接设置为tcp)
     *  >IPV4地址对(TLV_VT_IPV4PAIR:s_first表示起始地址，s_second表示结束地址)/
     *   IPV6地址对(TLV_VT_IPV6PAIR: s6_first表示起始地址，s6_second表示结束地址)/
     *   域名(TLV_VT_NCDNAME) 
     *   上述三者只会存三个
     *  >端口组(TLV_VT_PORTPAIR: first表示起始端口,second表示结束端口)
     */
    NC_CMD_RULE = 4, 

    /*
     *天擎控制中心ip地址V2版本(支持ipv4/ipv6,2.0.0.4300版本加入)
     *其Data格式如下:
     *IPV4地址(TLV_VT_IPV4),IPV6地址(TLV_VT_IPV6)
     *
     *Note: 两者允许同时有，但每个地址只允许有一个
     */
    NC_CMD_CCIP_V2,
    /*
     *NAC控制中心ip地址V2版本(支持ipv4/ipv6,2.0.0.4300版本加入)
     *其Data格式如下:
     *IPV4地址(TLV_VT_IPV4),IPV6地址(TLV_VT_IPV6)
     *
     * Note: 两者允许同时有，但每个地址只允许有一个
     */
    NC_CMD_NAC_CCIP_V2,

    /*
     *多网切换tls解析出的域名对应的ip下发指令(2.0.0.4300加入,之前的版本采用的旧的struct结构)
     *其Data格式如下:
     *|---匹配模式(TLV_VT_NCMODE)---|----地址(TLV_VT_IPV4/TLV_VT_IPV6,可以有多个)----|
     *匹配模式(对应字段类型为TLV_VT_NCMODE,对应值: NC_MODE_XXX)
     *IPV4地址(TLV_VT_IPV4)/IPV6地址(TLV_VT_IPV6) 可以有多个
     */
    NC_CMD_TLSIP, //tls协议解释出的域名对应的ip
};
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//主防AD
enum {
    AD_GID_NONE = 0, //无效gid
    AD_GID_TASKCREATE = 1, //进程创建
    AD_GID_LOADSO = 2, //so库
    AD_GID_LOADKO = 3, //驱动加载
    AD_GID_SHELLPIPE = 4,//shell管道防护(针对不落地病毒,5100版本引入)
    AD_GID_UNLOADKO = 5, //HJJ加入的驱动卸载防护
};

//主防op字段的值
enum {
    AD_OP_NONE = 0, //不做操作
    AD_OP_AUDIT = 1,//上报给用户态,只审计
    AD_OP_BLOCK = 2,//内核直接阻断,并审计
    AD_OP_QUERY = 3,//上报给用户态查询并确认(由用户态来确认是否放行)
};

//主防action字段的值
enum {
    AD_ACT_NONE = 0x0,//no event,don't care
    AD_ACT_OCR = 0x1,//open create
    AD_ACT_ORD = 0x2,//open readonly
    AD_ACT_OWR = 0x4,//open with write
    AD_ACT_CWR = 0x8,//close write
    AD_ACT_RENAME = 0x10,//rename
    AD_ACT_UNLINK = 0x20,//unlink
    AD_ACT_LINK = 0x40,//link,symlink
    AD_ACT_MKDIR = 0x80,//mkdir
    AD_ACT_RMDIR = 0x100,//rmdir
    AD_ACT_CHMOD = 0x200,//chmod,fchmod,fchmodat
    AD_ACT_CHOWN = 0x400,//chown,fchown,fchownat
    AD_ACT_TRUNC = 0x800,//truncate
    AD_ACT_CHATTR = 0x1000,//chattr,
};

//主防Task flag标记的可选值,参考的是文件系统的权限(mode)值
//我们在此处做了一些针对性处理,因为主防在进程启动时
//主要关心的是程序的可执行权限,下面的标识可以结合使用
//内核在判断下面权限时是通过(struct kstat->mode & flags) == flags来判断的，
//所以在设置一定要严格，对应的可执行文件权限必须都有时才会命中
enum {
    AD_TASK_FLAG_XUSR = 00100,//执行权限
    AD_TASK_FLAG_SUID = 04000, //set-user-id权限
};

//AD规则操作类型
enum {
    AD_RULE_OP_UPD = 1,//更新(upgrade)
    AD_RULE_OP_DEL,//删除
    AD_RULE_OP_CLEAN,//清理
};

//主防rootkit扫描项
enum {
    AD_RTSCAN_PROCFS = 1,//针对hook procfs的扫描
    AD_RTSCAN_SYSCALL = 2,//针对hook系统调用表的扫描
    AD_RTSCAN_HIDEKMOD = 3,//针对隐藏内核模块的扫描
};

/*
 *主防指令(用户态发给内核的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_AD)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_AD其Fields，格式如下:
 *|--1 Byte AD_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum AD_CMD_TYPE {
    /*
     *主防开关指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    AD_CMD_SWITCH = 1,

    /*
     *主防进程防护指令(目前只有一个开关)
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    AD_CMD_TASK = 2,

    /*
     *主防规则下发指令:
     *其Data格式如下:
     *
     *{
     * "op": 1,//可选值1,2,3
     * "file" : [{
     * }],
     * "proc": [{
     * }]
     }
     *file,proc均与ad.rule保持一致
     *根据op值不同,file,proc内容有所不同:
     *1.op值为AD_RULE_OP_UPD,file,proc与ad.rule文件中保持一致
     *2.op值为AD_RULE_OP_DEL,file,proc的值规则中的项目只需要id，不需要其他字段
     *3.op值为AD_RULE_OP_CLEAN,file,proc为空数组:这样做是为了灵活对不同类型的主防规则进行清理;
     *   如果file,proc均数组均没有，则不会触发任何清理操作
     */
    AD_CMD_RULE = 3,

    /*
     *主防nfs防护指令(目前只有一个开关)
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    AD_CMD_NFS = 4,
};

/*
 *主防事件通知
 **报文格式:
 *|--1 Byte product-type(TQ_PT_AD)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_AD其Fields，格式如下:
 *|--1 Byte AD_EVENT_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */

 //AD_EVENT_TYPE的可选值如下
enum {
    AD_EVENT_NONE = 0, //无效值，用于初始化时
    /*
     *主防文件访问事件通知
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *主防规则组ID(TLV_VT_ADGID),主防规则ID(TLV_VT_ADRID)
     *主防action(TLV_VT_ADACT),主防op值(TLV_VT_ADOP),
     *触发事件的文件路径(TLV_VT_PATH),
     *内核等待标识(TLV_VT_WAITKEY,该字段中有在主防op值为AD_OP_QUERY时才有)
     *父进程ID
     *
     *Note: 用户态收到对应消息后，需要根据主防op值做出判断，
     *当该值是AD_OP_QUERY时，用户态程序需要对对应的路径进行判断，并向内核返回结果
     *目前返回的值只需要0与非0，0表示内核需要放行,1表示内核需要拦截
     */
    AD_EVENT_FACCESS = 1,
     /*
     * 主防进程启动事件通知
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *主防规则组ID(TLV_VT_ADGID),主防规则ID(TLV_VT_ADRID)
     *主防flag(TLV_VT_ADFLAG),主防op值(TLV_VT_ADOP),
     *触发事件的文件路径(TLV_VT_PATH),
     *进程命令行参数(TLV_VT_CMDLINE 2.0.0.4300版本开放)
     *内核等待标识(TLV_VT_WAITKEY,该字段中有在主防op值为AD_OP_QUERY时才有)
     *父进程ID
     *
     *Note: 用户态收到对应消息后，需要根据主防op值做出判断，
     *当该值是AD_OP_QUERY时，用户态程序需要对对应的路径进行判断，并向内核返回结果
     *目前返回的值只需要0与非0，0表示内核需要放行,1表示内核需要拦截
     */
    AD_EVENT_TASK = 2,
    /*
     * 驱动加载事件通知
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *主防规则组ID(TLV_VT_ADGID),主防规则ID(TLV_VT_ADRID)
     *主防flag(TLV_VT_ADFLAG),主防op值(TLV_VT_ADOP),
     *触发事件的内核模块文件路径(TLV_VT_PATH),
     *驱动名称(TLV_VT_KONAME)
     *驱动srcver(TLV_VT_SRCVER,可能为空),驱动文件md5(TLV_VT_BINMD5)
     *内核等待标识(TLV_VT_WAITKEY,该字段中有在主防op值为AD_OP_QUERY时才有)
     *父进程ID
     *
     *Note: 用户态收到对应消息后，需要根据主防op值做出判断，
     *当该值是AD_OP_QUERY时，用户态程序需要对对应的路径进行判断，并向内核返回结果
     *目前返回的值只需要0与非0，0表示内核需要放行,1表示内核需要拦截
     */
    AD_EVENT_LOADKO = 3,//驱动加载的事件
    /*
     * 主防句柄防护事件
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *主防规则组ID(TLV_VT_ADGID),主防规则ID(TLV_VT_ADRID)
     *主防op值(TLV_VT_ADOP),主防规则MAXFD(TLV_VT_MAXFD),触发事件的句柄值(TLV_VT_FD),
     *触发事件的文件路径(TLV_VT_PATH),
     *父进程ID
     *
     */
    AD_EVENT_MFD = 4,//句柄打开过多事件(so many fd)
    /*
     *主防SO加载事件通知
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *主防规则组ID(TLV_VT_ADGID),主防规则ID(TLV_VT_ADRID)
     *主防flag(TLV_VT_ADFLAG),主防op值(TLV_VT_ADOP),
     *SO文件路径(TLV_VT_PATH),
     *内核等待标识(TLV_VT_WAITKEY,该字段中有在主防op值为AD_OP_QUERY时才有)
     *父进程ID
     *
     *Note: 用户态收到对应消息后，需要根据主防op值做出判断，
     *当该值是AD_OP_QUERY时，用户态程序需要对对应的路径进行判断，并向内核返回结果
     *目前返回的值只需要0与非0，0表示内核需要放行,1表示内核需要拦截
     */
    AD_EVENT_LOADSO,

    /*
     *主防nfs防护事件通知
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),
     *触发该事件的nfs客户端ip(TLV_VT_SIPV4/TLV_VT_SIPV6)
     *主防action(TLV_VT_ADACT,用于标识事件类型)
     *触发事件的文件路径(TLV_VT_PATH),
     *文件目地路径(TLV_VT_NPATH,该字段只有在文件事件为TLV_VT_AD是AD_ACT_RENAME时才有)
     */
    AD_EVENT_NFS,
    /*
     * 驱动卸载事件通知(HJJ加入的驱动卸载防护事件)
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *进程的可执行路径(TLV_VT_CMDLINE)
     *主防规则组ID(TLV_VT_ADGID),主防规则ID(TLV_VT_ADRID)
     *主防flag(TLV_VT_ADFLAG),主防op值(TLV_VT_ADOP),
     *驱动名称(TLV_VT_KONAME)
     *内核等待标识(TLV_VT_WAITKEY,该字段中有在主防op值为AD_OP_QUERY时才有)
     *父进程ID
     *
     *Note: 用户态收到对应消息后，需要根据主防op值做出判断，
     *当该值是AD_OP_QUERY时，用户态程序需要对对应的路径进行判断，并向内核返回结果
     *目前返回的值只需要0与非0，0表示内核需要放行,1表示内核需要拦截
     */
    AD_EVENT_UNLOADKO,
    /* 防勒索事件通知 */
    AD_EVENT_RANSOM,
};

////////////////////////////////////////////////////////////////////////////////
//自保的TLV通信消息

enum DEFENSE_OP_TYPE {
    DEFENSE_OP_UPGRADE = 1,//upgrade(不存在时添加，存在时更新)
    DEFENSE_OP_DELETE, //删除
    DEFENSE_OP_CLEAN //清理所有
};
/*
 *自保指令(用户态发给内核的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_SELF)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_AD其Fields，格式如下:
 *|--1 Byte DEFENSE_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum DEFENSE_CMD_TYPE {
     /*
     *自保PID列表下发指令
     *其Data格式如下:
     *操作标识(TLV_VT_OP,可选值为DEFENSE_OP_TYPE),
     *PID(TLV_VT_PID,可以有多个pid,多个pid时就需要有多个TLV_VT_PID)

     *当操作标识为DEFENSE_OP_CLEAN时，可以没有pid字段,此时会清理所有受保护的进程
     */
    DEFENSE_CMD_PIDS = 1,//自保pid列表

    /**
     * 自保文件或路径的列表下发指令
     * 其Data格式如下:
     * 操作标识(TLV_VT_OP,可选值为DEFENSE_OP_TYPE),
     * FILES(TLV_VT_PATH, 需要自保的路径)
     */
    DEFENSE_CMD_FILES = 2,//自保文件列表
};
///////////////////////////////////////////////////////////////////////////////

enum FILEFIRM_CMD_TYPE {
    /*
     *文件加固开关指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    FILEFIRM_CMD_SWITCH = 1,
};

/*
 *filefirm事件通知(内核发给用户态的)
 *报文格式:
 *|--1 Byte product-type(TQ_PT_FILEFIRM)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_FILEFIRM其Fields，格式如下:
 *|--1 Byte FILEFIRM_EVENT_LOG-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum FILEFIRM_EVENT_TYPE {
    /*
     * 文件加固日志事件通知
     *其Data格式如下:
     *进程PID(TLV_VT_PID)，PPID(TLV_VT_PPID),进程名(TLV_VT_COMM)
     *文件操作类型(TLV_VT_FILEFIRM_ACT)
     *文件路径(TLV_VT_PATH)
     *
     */
    FILEFIRM_EVENT_LOG = 1,
};

//FILEFIRM规则操作类型
enum {
    FILEFIRM_RULE_OP_UPD = 1,//更新(upgrade)
    FILEFIRM_OP_DEL,//删除
    FILEFIRM_OP_CLEAN,//清理所有
};

//文件加固action字段的值
enum {
    FILEFIRM_ACT_NONE = 0x0,//no event,don't care
    FILEFIRM_ACT_OCR = 0x1,//open create
    FILEFIRM_ACT_OWR = 0x2,//open with write
    FILEFIRM_ACT_CWR = 0x4,//close write
    FIELFIRM_ACT_RENAME = 0x8,//rename
    FILEFIRM_ACT_UNLINK = 0x10,//unlink
    FILEFIRM_ACT_LINK = 0x20,//link,symlink
    FILEFIRM_ACT_MKDIR = 0x40,//mkdir
    FILEFIRM_ACT_RMDIR = 0x80,//rmdir
    FILEFIRM_ACT_CHMOD = 0x100,//chmod,fchmod,fchmodat
    FILEFIRM_ACT_CHOWN = 0x200,//chown,fchown,fchownat
    FILEFIRM_ACT_TRUNC = 0x400,//truncate
    FILEFIRM_ACT_CHATTR = 0x800,//chattr,
    FILEFIRM_ACT_UTIMES = 0x1000, //utimes
};

//文件加固的日志上报类型
enum {
    FILEFIRM_DENY_LOG = 0,   //拦截的日志上报
    FILEFIRM_ALLOW_LOG,   //放行的日志上报
    FILEFIRM_ALL_LOG,     //所有日志上报
};

/**
 * @brief 防火墙规则分组类型定义
 */
enum FW_RULE_GROUP_ID {
    FW_GROUP_UNSPEC = 0, // 未定义 TQ_PT_NONE
    FW_GROUP_AUDIT,      // 审计 TQ_PT_AUDIT
    FW_GROUP_FW,         // 防火墙 TQ_PT_FW
    FW_GROUP_NC,         // 多网切换 TQ_PT_NC
    FW_GROUP_NETDET,     // 违规外联 TQ_PT_NETDETECT
    FW_GROUP_SCHECK,     // 安检合规 TQ_PT_SC
    FW_GROUP_EDR,        // EDR TQ_PT_EDR
    FW_GROUP_SOFTWARE,   // 软件管家 TQ_PT_SOFTWARE
    FW_GROUP_SECASSESS,  // 安全评估 TQ_PT_NONE，目前没有定义
    FW_GROUP_KERNEL,     // base libEntKernel.so 全局加白防火墙使用 TQ_PT_KERNEL
    FW_GROUP_MAX = 32,   // 32
};

/**
 * @brief 防火墙规则优先级
 * @FW_PRIORITY_WHITE: 优先级最高，常用于控制中心加白等
 */
enum FW_RULE_PRIORITY {
    FW_PRIORITY_WHITE = 0,
    FW_PRIORITY_1,
    FW_PRIORITY_2,
    FW_PRIORITY_3,
    FW_PRIORITY_4,
    FW_PRIORITY_5,
    FW_PRIORITY_6,
    FW_PRIORITY_7,
    FW_PRIORITY_MAX = FW_PRIORITY_7 + 1, // 8
};


//防火墙域名(url)匹配模式(firewall domain-name match-type)
enum FW_DNAME_MTYPE{
    FW_DNAME_MFULL = 0, //全词匹配(www.baidu.com)
    FW_DNAME_MPRE  = 1, //前向模糊匹配(www.baidu.*)
    FW_DNAME_MMENT  = 2, //后向模糊匹配(*.baidu.com)
    FW_DNAME_MPREMENT  = 3,//前后项模糊匹配(*.baidu.*)
};

//防火墙的TLV通信消息
enum FW_OP_TYPE {
    FW_OP_NONE = 0,//不做操作
    FW_OP_AUDIT = 1,//只审计
    FW_OP_BLOCK,//阻止并审计
    FW_OP_QUERY,//询问用户态
};

enum FW_NF_RC {
    FW_NF_NONE = -1,
    FW_NF_ACCEPT = 0,
    FW_NF_DROP = 1,
    FW_NF_CONTINUE = 2,
};

enum {
    FW_CMDEXE_CLEAN = 0, //清理
    FW_CMDEXE_ADD = 1, //添加
};

/*
 *fw指令(用户态发给内核的)
 **报文格式:
 *|--1 Byte product-type(TQ_PT_FW)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_FW其Fields，格式如下:
 *|--1 Byte FW_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum FW_CMD_TYPE {
    /*
    *fw下发的开关指令
    *其Data格式如下:
    *开关标识(TLV_VT_SWITCH),
    *日志全量上报标识(TLV_VT_FWLOGALL,可以没有该字段)
    *LOOPBACK接口报文过滤标识(TLV_VT_FWSKIPLOOPBACK,可以没有该字段)
    */
    FW_CMD_SWITCH = 1,
     /*
     *fw下发的应用联网控制指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH),
     *操作标识(TLV_VT_OP,可选值FW_OP_TYPE)
     */
    FW_CMD_APPNET = 2,//应用联网控制
    /*
     *fw防火墙命令程序列表
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH)
     *操作标识(TLV_VT_FWCMDEXEOP,0,1)
     *防火墙命令可执行程序完整路径(TLV_VT_FWCMDEXE,可以有多个)
     */
    FW_CMD_CMDEXE = 3,
    /*
     *fw查找skb->sk开关
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,0,1)
     */
    FW_CMD_LOOKUP_SK = 4,
};

/*
 *fw事件通知(内核发给用户态的)
 *报文格式:
 *|--1 Byte product-type(TQ_PT_FW)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_FW其Fields，格式如下:
 *|--1 Byte FW_EVENT_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum FW_EVENT_TYPE {
    /*
     * 应用联网事件通知
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *防火墙op(TLV_VT_OP)
     *触发事件的程序文件路径(TLV_VT_PATH)
     *内核等待标识(TLV_VT_WAITKEY,该字段只有在op值为FW_OP_QUERY时才有)
     *
     *Note: 用户态收到对应消息后，需要根据op值做出判断，
     *当该值是FW_OP_QUERY时，用户态程序需要对对应的路径进行判断，并向内核返回结果
     *目前返回的值只需要0与非0，0表示内核需要放行,1表示内核需要拦截
     */
    FW_EVENT_APPNET = 1,
    /*
     *ipv4防火墙事件通知
     *其Data格式如下:
     *防火墙规则ID(TLV_VT_FWRID),报文处理结果(TLV_VT_FWNFRC)
     *ip层协议标识(TLV_VT_IPPROTO,可选值:IPPROTO_TCP,IPPROTO_UDP,IPPROTO_ICMP,这些值都是系统预定义的值)
     *流入接口名称(TLV_VT_FWINIF,对于外出报文，没有该字段),流出接口名(TLV_VT_FWOUTIF,对于流入报文，没有该字段)
     *源ip(TLV_VT_SIPV4),目地ip(TLV_VT_DIPV4),源MAC(TLV_VT_SDEVADDR,流入报文才有),目标MAC(TLV_VT_DDEVADDR，流入报文才有)
     *源port(TLV_VT_SPORT,该字段可能没有),目标port(TLV_VT_DPORT,该字段可能没有)
     *匹配成功的精确域名(TLV_VT_FWDNAME,该字段只在url防火墙匹配成功时才有,其他情况均没有)
     */
    FW_EVENT_IP4T,

    /*
     *arp防火墙事件通知
     *其Data格式如下:
     *防火墙规则ID(TLV_VT_FWRID),报文处理结果(TLV_VT_FWNFRC)
     *流入接口名称(TLV_VT_FWINIF,对于外出报文，没有该字段),流出接口名(TLV_VT_FWOUTIF,对于流入报文，没有该字段)
     *源ip(TLV_VT_SIPV4),目地ip(TLV_VT_DIPV4),源MAC(TLV_VT_SDEVADDR),目标MAC(TLV_VT_DDEVADDR)
     */
    FW_EVENT_ARPT,

      /*
     *ipv6防火墙事件通知
     *其Data格式如下:
     *防火墙规则ID(TLV_VT_FWRID),报文处理结果(TLV_VT_FWNFRC)
     *ip层协议标识(TLV_VT_IPPROTO,可选值:IPPROTO_TCP,IPPROTO_UDP,IPPROTO_ICMPV6,这些值都是系统预定义的值)
     *流入接口名称(TLV_VT_FWINIF,对于外出报文，没有该字段),流出接口名(TLV_VT_FWOUTIF,对于流入报文，没有该字段)
     *源ip(TLV_VT_SIPV6),目地ip(TLV_VT_DIPV6),源MAC(TLV_VT_SDEVADDR,流入报文才有),目标MAC(TLV_VT_DDEVADDR，流入报文才有)
     *源port(TLV_VT_SPORT,该字段可能没有),目标port(TLV_VT_DPORT,该字段可能没有)
     *匹配成功的精确域名(TLV_VT_FWDNAME,该字段只在url防火墙匹配成功时才有,其他情况均没有)
     */
    FW_EVENT_IP6T,
};
///////////////////////////////////////////////////////////////////////////////

/*
 *rfc1035: 
 *dns rcode值:
 *  0：无差错
 *  1：查询格式错
 *  2：服务器失效
 *  3：域名不存在
 *  4：查询类型未实现(服务器不支持此类dns请求)
 *  5：查询被拒绝
 *  6-15: 保留未用
 */
enum {
    DNS_RC_OK = 0,//dns解析成功
    DNS_RC_BADFMT = 1,
    DNS_RC_SVRFAIL = 2,
    DNS_RC_NODNAME = 3,
    DNS_RC_NOTSUPP = 4,
    DNS_RC_DENY = 5,
    //6-15 reserved
    DNS_RC_TIMEDOUT = 15,//dns解析超时(我们自己定义的错误码)
};

enum DNS_RR_TYPE {
    DNS_RR_A = 1, //ipv4 (rfc1035)
    DNS_RR_CNAME = 5, //cname (rfc1035)
    DNS_RR_AAAA = 28, //ipv6 (rfc3596)

    DNS_RR_RESERVED = 65535
};

enum DNS_LOG_TYPE {
    DNS_LOG_NF = 1, //内核解析网络包(netfilter方式)
    DNS_LOG_PRELOAD = 2, //用户态preload方式
};

/*
 *EDR指令(用户态发给内核的)
 *从2.0.0.4550开始，EDR策略层不再提供总的开关指令
 *后期如果想通过策略控制EDR总功能，则需要考虑向前兼容
 *
 *内核层为了保持向前兼容做了如下调整
 * a) EDR总开关默认开启，但可以在调试时通过sysfs接口关闭
 * b) EDR所有功能单元均受总开关控制
 * c) EDR各业务功能单元均有单独的开关控制
 **报文格式:
 *|--1 Byte product-type(TQ_PT_EDR)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_EDR其Fields，格式如下:
 *|--1 Byte EDR_CMD_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum EDR_CMD_TYPE {
    /*
     *EDR开关指令,这个同时控制了DNS的功能,
     *后期直接使用它来控制DNS功能吧
     *
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    EDR_CMD_SWITCH = 1,
    #define EDR_CMD_DNS  EDR_CMD_SWITCH
    /*
     *断网开关指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    EDR_CMD_NETDENY = 2,

    /*
     *EDR程序启动管控开关指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    EDR_CMD_EXEC = 3,

     /*
     *EDR加载so开关指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    EDR_CMD_LOADSO = 4,

    /*
     *端口探测开关指令
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    EDR_CMD_DETECTPORT = 5,

    /*
     *U盘审计开关指令(2023.11.07 型研edr加入)
     *其Data格式如下:
     *开关标识(TLV_VT_SWITCH,为0表示关闭,1表示开启)
     */
    EDR_CMD_UDISK_SWITCH = 6,

    /**
     * U盘路径的列表下发指令(2023.11.07 型研edr加入   )
     * 其Data格式如下:
     * 操作标识(TLV_VT_OP,可选值为EDR_UDISK_OP_TYPE),
     * FILES(TLV_VT_PATH, 需要审计的路径，结尾以‘/‘)
     */
    EDR_CMD_UDISK_PATH = 7,

};

enum EDR_UDISK_OP_TYPE {
    EDR_UDISK_OP_UPGRADE = 1,//upgrade(不存在时添加，存在时更新)
    EDR_UDISK_OP_DELETE, //删除
    EDR_UDISK_OP_CLEAN //清理所有
};

/*
 *edr事件通知(内核发给用户态的)
 *报文格式:
 *|--1 Byte product-type(TQ_PT_EDR)--|--2Byte length--|--Fields--|
 *Fields可以有多个;但对于TQ_PT_EDR其Fields，格式如下:
 *|--1 Byte EDR_EVENT_TYPE-|--2 byte Data-Length--|--Data--|
 *Data也是由多个TLV格式的不同值组成
 */
enum EDR_EVENT_TYPE {
    /*
     * DNS查询事件
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),
     *进程euid(TLV_VT_EUID),进程session-id(TLV_VT_TSID)
     *DNS rcode(TLV_VT_DNSRC)
     *DNS查询类型(TLV_VT_DNSTYPE,可能没有)
     *DNS日志类型(TLV_VT_DNSLOGTYPE,可能没有)
     *触发事件的程序文件路径(TLV_VT_PATH)
     *DNS查询的域名(TLV_VT_DNAME)
     *域名对应的IP(TLV_VT_IPV4/TLV_VT_IPV6,可能没有)
     *查询时间(TLV_VT_TIMESTAMP)
     */
    EDR_EVENT_DNS = 1,

    /*
     *EDR程序执行事件(2022.08军队V10 EDR型研加入)
     *此处全部使用原始文件相关值Data包含:
     *进程PID，进程名(TVL_VT_COMM),进程可执行文件路径(TLV_VT_PATH),
     *进程real-uid,进程effective-uid,进程real-gid,进程effective-gid
     *内核等待标识(TLV_VT_WAITKEY)
     */
    EDR_EVENT_EXEC = 2,

    /*
     *EDRSO加载事件通知(2023.01军队V10  EDR型研加入)
     *其Data格式如下:
     *进程PID，进程名(TLV_VT_COMM),进程euid(TLV_VT_EUID)
     *SO文件路径(TLV_VT_PATH),
     *父进程ID
    */
    EDR_EVENT_LOADSO = 3,

    /*
     *EDR 网络连接阻断 FW日志上报标识
    */
    EDR_EVENT_FWLOG = 4,

    /*
     * 端口探测事件通知 (2023-05-18 EDR销许测评加入)
     * 其Data格式如下:
     * 远端IP（TLV_VT_IPV4/TLV_VT_IPV6）
     * 探测端口（TLV_VT_DPORT）
     */
    EDR_EVENT_DETECTPORT = 5,

    /*
     *EDR的U盘审计事件(2023.11军队V10 EDR型研加入)
     *此处全部使用原始文件相关值Data包含:
     *进程PID，进程名(TVL_VT_COMM),进程可执行文件路径(TLV_VT_PATH),
     *进程effective-uid
     *进程PPID
     */
    EDR_EVENT_UDISK = 6,
};

/////////////////////////////////////////////////////
// sockopt
// base for ktq socket options
#define KTQ_SOCKOPT_BASE (4096 + 2048)

enum sockopt_ctl {
    KTQ_SOCKOPT_UNSPEC = 0,
    KTQ_SOCKOPT_TLV_SUBS, // tlv子系统
    KTQ_SOCKOPT_FW,       // 防火墙模块
    KTQ_SOCKOPT_FWF,      // 防火墙框架
    KTQ_SOCKOPT_MAX = 0xFF,
};

#define KTQ_SOCKOPT_CTL_CMD(ctl) (ctl + KTQ_SOCKOPT_BASE)
#define KTQ_SOCKOPT_CMD_CTL(cmd) (cmd - KTQ_SOCKOPT_BASE)

// 防火墙框架
enum SOPT_FWF_CMD {
    SOPT_FWF_APPMAP = 1,
};

//charater device
typedef struct {
    uint16_t type;//对应前面user向kernel发送的NL_POLICY_XXX
    uint16_t len;//data的长度
    void* addr; //用户空间地址
}ktq_data_t;

//内核发给用户态的数据格式
struct ktq_msg_data {
    int data_type;//对应前面kernel向user发送的NL_POLICY_XXX_NOTIFY
    int data_len;
    char data[0];
};

//这个是针对AK7,将报文限定变成16KB
#define KTQ_NEW_DATA_MAX 16384

#define KTQ_DATA_MAX 8192
#define KTQ_IOC_MAGIC ('T' + 'Q')
#define KTQ_IOC_SETVAL (_IOW(KTQ_IOC_MAGIC, 0x1,ktq_data_t))

#define KTQ_SET_DATA(data,_type,_len,_paddr) \
                    data.type = _type;      \
                    data.len = _len;         \
                    data.addr = _paddr;





//密标文件头部长度
#define KTQ_MB_FHEAD_LEN 256
//密标文件除首部外，余下的部分文件大小分节单位
#define KTQ_MB_FSEG_SIZE 264
//密标文件的组成是:密标控制属性段(256字节) + 密标属性(至少264字节) + 密标正文(至少264字节) 
//密标文件的最小值:首部(256字节) + 密标属性(至少264字节) (密标正文可以没有)
#define KTQ_MB_FMIN (KTQ_MB_FHEAD_LEN + KTQ_MB_FSEG_SIZE)

#define KTQ_CDEV_NAME  "osecbz1"
#define KTQ_CDEV_PATH  "/dev/osectest"

#define KTQ_OSEC_NAME "MagicArmor_0"


//#define KTQ_CDEV_NAME  "qaxmjbz1"
//#define KTQ_CDEV_PATH  "/dev/qaxmjbz1"

//奇安信密级标记名称标示,其格式类似:QAXMJBZWJTX3,其中QAXMJBZ是固定的
//WJTX3可能会变化，所以此处只验证QAXMJBZ
#define KTQ_MJBZ_NAME "QAXMJBZ"
#define KTQ_MJBZ_EXEC "/opt/MJBZGL/MJBZGL/QAX/QAXMJBZUI2" //压缩包的重定向应用
#define KTQ_MJBZ_EXEC1 "/opt/MJBZGL/MJBZGL/QAX/QAXMJBZUI4" //针对文件管理器重定向应用

// 奇安信信息隐藏名称标识,其格式类似:QAXXXYCYWTX2,其中QAXXXYC是固定的
// YWTX2可能会变化, 所以此处只验证QAXXXYC
#define KTQ_XXYC_NAME "QAXXXYC"

/////////////////////////////////////////////////////
//导出的sysfs协议接口文件,通过该文件能够获取内核开启的netlink端口及char-dev标识
#if 0
#ifdef QAXMJBZ
    //密标
    #define KTQ_SYSFS_NAME   "qaxmb"
#elif defined(ZYJ_AUDIT)
    //专用机主审
    #define KTQ_SYSFS_NAME   "qaxzyjaudit"
#elif defined(QAXYC)
    //隐写
    #define KTQ_SYSFS_NAME   "qaxyc"
#elif defined(QAXTJ)
    //安全套件
    #define KTQ_SYSFS_NAME   "qaxtj"
#elif defined(GWTJ)
    //长城定制版安全套件
    #define KTQ_SYSFS_NAME   "gwtj"
#else
    #define KTQ_SYSFS_NAME   "qax"
#endif
#endif
#define KTQ_SYSFS_NAME   "osec"

#define KTQ_SYSFS_PROTO "/sys/" KTQ_SYSFS_NAME "/proto"

////////////////////////////////////////////////////

//公司名称标识
#define KTQ_COMP_NAME	"MagicArmor_0"

//天擎终端UI程序前缀标识
#define KTQ_TQUI_NAME  "sqaxsafe"

////////////////////////////////////////////////////////

///tq-char-mmap:基于字符设备的mmap
/*
   Frame structure:

   - Start. Frame must be aligned to KTQ_MMC_ALIGNMENT=16
   - struct ktq_mmc_req
   - pad to KTQ_MMC_ALIGNMENT=16
   - Gap, chosen so that packet data (Start + ktq_mmc_hdr) alignes to KTQ_MMC_ALIGNMENT=16
   - Pad to align to KTQ_MMC_ALIGNMENT=16

   * frames_per_block =  block_size/ frame_size
	indeed, packet_set_ring checks that the following condition is true
		frames_per_block * block_nr == frame_nr
	Lets see an example, with the following values:
		block_size= 4096
		frame_size= 2048
		block_nr  = 4
		frame_nr  = 8
	we will get the following buffer structure:
			block #1                 block #2 
	+---------+---------+    +---------+---------+ 
	| frame 1 | frame 2 |    | frame 3 | frame 4 | 
	+---------+---------+    +---------+---------+   

			block #3                 block #4 
	+---------+---------+    +---------+---------+ 
	| frame 5 | frame 6 |    | frame 7 | frame 8 | 
	+---------+---------+    +---------+---------+
 *
 *Note:
 *一个报文可能会占用多个frame,但一个报文必须保证在一个block中，不能跨block
 */

struct ktq_mmc_req {
	unsigned int	block_size;	/* Minimal size of contiguous block */
	unsigned int	block_nr;	/* Number of blocks */
	unsigned int	frame_size;	/* Size of frame */
	unsigned int	frame_nr;	/* Total number of frames */
};

#define KTQ_MMC_ST_KERN		0
#define KTQ_MMC_ST_USER		1
#define KTQ_MMC_ST_LOSING	(1 << 2)

struct ktq_mmc_hdr
{
	unsigned long	status;
	unsigned int	snaplen;
};

#define KTQ_MMC_ALIGNMENT	16
#define KTQ_MMC_ALIGN(x)	(((x)+KTQ_MMC_ALIGNMENT-1)&~(KTQ_MMC_ALIGNMENT-1))
#define KTQ_MMC_HDRLEN		(KTQ_MMC_ALIGN(sizeof(struct ktq_mmc_hdr)))


struct ktq_pack_stats
{
	unsigned long	packets;
	unsigned long	drops;
};

#define KTQ_MMC_SET_RING	0x10

#define KTQ_IOC_SETRING (_IOW(KTQ_IOC_MAGIC,KTQ_MMC_SET_RING,struct ktq_mmc_req))

#define KTQ_SYSFS_MMC "/sys/" KTQ_SYSFS_NAME "/mmc"
///////////////////////////////////////////////////////////////////////////////////////



struct netlink_netlog {
    int start_idx;
    int end_idx;
    int max_idx;
};


struct osec_global_dir{
    uint8_t _type;
    char name[255];
    uint8_t name_len;
};


struct NetworkKernelRulesInfo{
    uint8_t addr_type:5,
            protocol:1; //1-tcp,0-udp
 //   uint32_t sip;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }sip;

    uint16_t sport;
//    uint32_t eip;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }eip;

    uint16_t eport;
    uint16_t redirectPort;
};

struct NetworkKernelPolicyInfo
{
    uint16_t pol_switch:1,
            acl_type:1,
            acl_num:8;
    struct NetworkKernelRulesInfo rules_info[20];
};


struct osec_network_report 
{
//    uint32_t type;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }src;
    uint16_t src_port;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }dst;
    uint16_t dest_port;
    uint32_t pid;
    char comm[32];
    //char dns_name[255];
};

struct osec_network_report_old 
{
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }src;
    uint16_t src_port;
    union {
        struct {
            uint32_t pad[3];
            uint32_t ip4;
        };
        uint16_t ip6[8];
        uint8_t as_u8[16];
        uint64_t as_u64[2];
    }dst;
    uint16_t dest_port;
    uint32_t pid;
    char comm[32];
    uint8_t type;
    //char dns_name[255];
};

struct osec_dns_report 
{
    uint32_t type;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint32_t pid;
    char comm[32];
    uint8_t is_ipv6:1,
            ip_cnt:4;
    union {
        uint32_t ipv4[12];
        uint8_t ipv6[48];
    };
    char dns_name[255];
};


struct osec_openport_report 
{
    uint32_t type;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dest_ip;
    uint32_t attack_dest_ip;
    uint16_t dest_port;
    uint32_t pid;
    char comm[32];
};

struct defense_action {
    int action;
    void* pwait_flag; 
};
struct av_file_info {
    int pid;
    int ppid;
    int uid;
    void* pwait_flag;
    char comm[512];
    char comm_p[16];
    char path[1024];
    char dst_path[1024];
    uint16_t type;
    uint32_t is_dir:3,
        deny:3,
        is_monitor_mode:2,
        rules_type:4,
        rules_idx:8,
        protect_rw:6,
		is_file:1;
};


struct av_self_protection_info {
    int pid;
    int ppid;
    int uid;
    int type;
    char comm[512];
    char comm_p[16];
    char path[1024];
    char dst_path[1024];
};

//charater device
typedef struct {
    uint16_t type;//对应前面user向kernel发送的NL_POLICY_XXX
    uint16_t len;//data的长度
    void* addr; //用户空间地址
}kosecs_data_t;

//内核发给用户态的数据格式
struct kosecs_msg_data {
    int data_type;//对应前面kernel向user发送的NL_POLICY_XXX_NOTIFY
    int data_len;
    char data[0];
};




/////////////////////////////////////////////////////
//导出的sysfs协议接口文件,通过该文件能够获取内核开启的netlink端口及char-dev标识
////////////////////////////////////////////////////

enum DEFENSE_TYPE {
    FILE_CREATE = 0,
    FILE_REMOTE = 1,
    FILE_MODIFY = 2,
    FILE_OPEN = 3,
    FILE_RENAME = 4,
    PROCESS_CREATE = 5,
    FILE_CLOSE = 6

};

#endif
