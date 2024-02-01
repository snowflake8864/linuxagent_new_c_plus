#ifndef GLOBAL_MESSAGE_H
#define GLOBAL_MESSAGE_H
#include <string>
#include <map>
#include <vector>
#include <list>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdint.h>

typedef struct SERVER_ADDRESS {
    std::string strServerIP;
    std::string strServerPort;
}SERVER_ADDRESS;

enum TASK_TYPE  {
    TASK_UPLOAD_PROCESS = 0,
    TASK_UPDATE,
    TASK_UPLOAD_DIR,
    TASK_DOWN_WHITE,
    TASK_DOWN_DIR_POLICY,
    TASK_UPLOAD_CONF, //no use
    TASK_DOWN_CONF,
    TASK_DOWN_BLACK,
    TASK_DOWN_FILE_TTAP = 8,
    TASK_UPLOAD_PORT = 9,
    TASK_DOWN_VIRTUAL_PORT =10,
    TASK_AUTODOWN_NETBLOACK_POLICY =11,// no use
    TASK_AUTOUPLOAD_NETBLOACK_POLICY =12, //no use
    TASK_DOWN_NETBLOACK_POLICY=13,
    TASK_DOWN_WHITE_IP_POLICY=14, //no use
    TASK_DOWN_BLACK_IP_POLICY=15,
    TASK_DOWN_USB_UPLOAD=16,
    TASK_DOWN_USB_DOWN=17, //no use
    TASK_DOWN_EXTORT = 19,
    TASK_UPLOAD_PROCESS_MODULE = 21,
    TASK_UPLOAD_ALL_PROCESS_MODULE = 22,
    TASK_UPLOAD_PROCESS_WHITE_MODULE = 23,
    TASK_UPLOAD_PROCESS_BLACK_MODULE =  24,
    TASK_UNINSTALL =  25,
    TASK_getwhiteperipherals = 26,
    TASK_getblackperipherals= 27,
    TASK_UPLOADSAMPLE= 28,
    TASK_SYSLOG_ENABLE = 29,//no use
    TASK_SYSLOG_DISABLE = 30, //no use
    TASK_GLOBAL_DIR = 33,
    TASK_GLOBAL_PROC = 31,
};

typedef struct TASK_BASE {
    std::list<TASK_TYPE> lst_type;
}TASK_BASE;

typedef struct BASE_ONLINE {
    std::string uid;
    std::string macid;
    std::string ip;
    std::string ver;
    int type;
    std::string os;
    std::string memsize;
    std::string cpu;
    std::string hdsize;
    std::string astarttime;
    std::string osstarttime;
    std::string auth;
    std::string userid;
    std::string host_name;
}BASE_ONLINE;


struct Audit_PROCESS{
    long        nTime;
    std::string strName;
    std::string strVendor;
    std::string strPackage;
    int         nProcessID;
    int         nParentID;
    int         nPriority;
    int         nThreadCount;
    long        nWorkingSetSize;
    std::string strStartTime;
    std::string strExecutablePath;
    std::string strUser;
    std::string hash;
    std::vector<std::string> map_depends;
};
struct Audit_SelfProtect{
    long        nTime;
    int         nType;
    int         nLevel;
    std::string procDir;
    std::string hash;
    std::string param;
    std::string fileDir;
    std::string targetDir;
};
struct FILE_INFO {
    std::string dir;
    std::string rw;
    std::string group;
    std::string user;
    std::string size;
    std::string starttime;
    std::string updatetime;
    std::string level;
    std::string dirtype;
    std::string hash;
    int type;
    int id;
};

struct LOG_INFO {
    std::string file_path;
    std::string md5;
    int nType;
    int nLevel;
    long nTime;
    std::string rename_dir;
    std::string notice_remark;
    std::string exception_process;
    std::string peripheral_name;
    std::string peripheral_remark;
    std::string peripheral_eid;
    std::string p_param;
};

typedef struct CONFIG_INFO {
    std::string serveripport;
    std::string logipport;
    int logproto;
    int logsent;
    int proc_protect;
    int file_protect;
    int crontime;
    int extortion_protect;
    int proc_switch;
    int module_switch;
    int file_switch;
    int usb_protect;
    int open_port_switch;
    int usb_switch;
    int extortion_switch;
    int api_port;
    int syslog_port;
    int syslog_switch;
    int self_protect_switch;
    int syslog_dns_switch;
    int syslog_outer_switch;
    int syslog_inner_switch;
    int syslog_process_switch;
    int syslog_login_switch;
    int hardware_switch;
    int hardware_time;
}CONFIG_INFO;

typedef struct  POLICY_PROTECT_DIR {
    int id;
    std::string dir;
    int type; //1: 文件夹　2:文件
    std::string hash;  
    int  protect_rw;  // 1:读取 2:写入 4:删除 8:重命名, 16:新建
    std::string file_ext;  //排除文件类型
    std::string include_file;  //保护文件类型
    int         is_extend; //1：集成　2:不继承
    std::string is_white;
    std::string white_hash;
}PROTECT_DIR;

typedef struct POLICY_RPOCESS_WHITE{
    std::string dir;
    std::string hash;
}POLICY_RPOCESS_WHITE;

typedef struct POLICY_UPDATE {
    std::string hash;
    std::string downurl;
}POLICY_UPDATE;

typedef struct POLICY_SINGLE_PROCESS_SO{   
    int pid;
    std::string hash;
} POLICY_SINGLE_PROCESS_SO;

typedef struct POLICY_PROCESS_MODULE_SO{   
    int moduleId;
    std::string dir;
    std::string hash;
} POLICY_PROCESS_MODULE_SO;


typedef struct POLICY_EXIPOR_PROTECT{
    int type;
    int index;
    std::string file_type;
    std::map<std::string, std::string> map_comm;
    std::string remark;
} POLICY_EXIPOR_PROTECT;


typedef struct DIR_VIEW {
    std::string dir;
    int type;
    int id;
} DIR_VIEW;

typedef struct PORT_BUSINESS_LIST {
    long        nTime;
    std::string strProtocol;
    std::string strLocalIP;
    int         nLocalPort;
    std::string strRemoteIP;
    std::string strRemotePort;
    std::string status;
    int         nPID;
    std::string strProcessPath;
} PORT_BUSINESS_LIST;



typedef struct PORT_REDIRECT {
    int  id;
    std::string type;
    int alarm_level;
    std::string source_ip;
    std::string source_port;
    std::string dest_ip;
    std::string dest_port;
    std::string protocol;
} PORT_REDIRECT;

typedef struct NET_PROTECT_IP {
    int table_serial;
    std::string ip;
    int direction;
    int type;   //1 :黑名单； 2：白名单
} NET_PROTECT_IP;

typedef struct pOpenPort {
    int weight;
    int time;
    std::string attack_ip;
    std::string destination_ip;
    int open_port;
    std::string redirect_ip;
    int redirect_port;
} pOpenPort;

typedef struct NETBLOCK {
    std::string ip;
    std::string type;
    std::string typeName;
    std::string starttime;
    std::string endtime;
    int direction;
} NETBLOCK;

typedef struct USB_INFO {
    std::string eid;
    std::string name;
    std::string intro;
    std::string type;
    int nAllow;
} USB_INFO;

typedef struct SAMPLE_INFO {
    int aid;
    std::string p_dir;
    std::string p_hash;
} SAMPLE_INFO;

typedef struct SYSLOG_INFO {
    int api_port;
    int syslog_port;
    //int syslog_switch;
    int syslog_process_switch;
    int proc_switch;
} SYSLOG_INFO;

typedef struct SYLOG_DNS_LOG {
    std::string uid;
    int p_id;
    std::string p_dir;
    std::string domain_name;
    std::string res_ip;
    int time;
    int log_type;
    std::string hash;
} SYSLOG_DNS_LOG;

typedef struct SYSLOG_NET_LOG {
    std::string uid;
    int p_id;
    std::string p_dir;
    std::string res_ip;
    int rs_port;
    int proto;
    int time;
    int log_type;
    std::string hash;
    std::string source_ip;
    int source_port;
} SYSLOG_NET_LOG;

typedef struct EDRPROCESS_LOG {
    std::string uid;
    std::string hash;
    int p_id;
    std::string p_dir;
    std::string p_param;
    std::string pp_hash;
    int pp_id;
    std::string pp_dir;
    std::string pp_param;
    int time;
    int log_type;
} EDRPROCESS_LOG;

struct FirewallRule {
    int id;
    int operation;  // 1拒绝 2允许
    int priority;  // 0最低 1低 2普通 3高 4最高
    int direction;  // 1流入 2流出 3任意
    std::string name;
    std::string local_ip;
    std::string local_port;
    std::string remote_ip;
    std::string remote_port;
    std::string ptcol;  // 协议 6:TCP 17:UDP 6,17TCP+UDP 1:ICMP
    bool need_log;
};

struct GlobalTrusrDir {
    int type;
    std::string dir;
    int is_extend;
};

struct LinuxDirProc {
    std::string dir;
    std::string hash;
    std::string introduce;
    std::string copyright;
};

typedef struct SYLOG_SSH_LOG {
    std::string ip;
    std::string username;
    std::string type;
    int status;
    int log_type;
    int time;
} SYLOG_SSH_LOG;

typedef struct RES_TOP {
    std::string id;
    std::string dir;
    std::string hash;
    std::string cpu_usage;
    std::string mem_size;
    std::string user;
} RES_TOP;

typedef struct RES_LOG {
    std::string hd_size;
    std::string hd_usage;
    std::string cpu_number;
    std::string cpu_usage;
    std::vector<RES_TOP> cpu_tops;
    std::string mem_size;
    std::string mem_usage;
    std::vector<RES_TOP> mem_tops;
    std::string self_mem_size;
    std::string self_cpu_usage;
} RES_LOG;

#endif /* GLOBAL_MESSAGE_H */


