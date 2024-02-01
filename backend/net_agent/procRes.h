#ifndef PROC_RES_H
#define PROC_RES_H

#include <sys/types.h>
#include <string>
#include <map>
#include <vector>

typedef struct PROCESS_INFO_S {    
    uint32_t iskthread;         //1内核进程，0普通进程
    uint32_t pid;               //进程id
    uint32_t ppid;              //父进程id
    uint32_t mem_size;          //实际占用的物理内存，kB
    int32_t priority;           //优先级
    uint32_t thread_count;      //线程数
    int64_t start_time;         //启动时间
    float cpu_percent;          //cpu利用率
    char user_name[32];         //所属用户
    char exec_name[32];         //可执行文件名
    char exec_path[256];        //可执行文件的绝对路径
    char parent_exec_path[256]; //父进程可执行文件的绝对路径
    char cmdline[256];          //命令行
    char package[256];          //所属安装包
}PROCESS_INFO_T;

typedef int CECode;
#define  CE_ERROR_OK 0
#define  CE_ERROR_OPEN_FILE -1
#define  CE_ERROR_NO_MEMORY -2
#define  CE_ERROR_DATA -3
#define  CE_ERROR_UNKNOWN -4
// #define  CE_ERROR_NO_MEMORY -5
// #define  CE_ERROR_NO_MEMORY -6
// #define  CE_ERROR_NO_MEMORY -7
class CProcInfo
{
public:
    CProcInfo(){};
    ~CProcInfo(){};

public:
    /*
    * 描述：获取当前系统进程信息(包括进程id，父进程id，所属用户，命令行等)
    * 参数：info 用于接收获取到的数据内容; size用于接收获取到的数据个数;
    * 返回值：错误码
    */
    CECode GetProcInfo(PROCESS_INFO_T** info, int *size);
    CECode SortCpu(std::vector<PROCESS_INFO_T> &vecInfo);
    CECode SortMem(std::vector<PROCESS_INFO_T> &vecInfo);
    void GetSelf(std::vector<PROCESS_INFO_T> vecInfo, long &cpuPercent, long &memSize);
private:
    /*
    * 描述：获取进程status文件的信息(包括pid,ppid,user_name,exec_name,mem_size,thread_count)
    * 参数：strPid 需要查询的进程pid; proc 用于保存结果的引用;
    * 返回值：错误码
    */
    CECode _ParseStatusFile(const char *strPid, PROCESS_INFO_T &proc);
    /*
    * 描述：获取系统启动时间保存到m_nSysBootTime
    * 参数：无
    * 返回值：错误码
    */
    CECode _GetSysBootTime();
    /*
    * 描述：获取进程stat文件的信息(包括进程优先级，启动时间)
    * 参数：strPid 需要查询的进程pid; proc 用于保存结果的引用;
    * 返回值：错误码
    */
    CECode _ParseStatFile(const char *strPid, PROCESS_INFO_T &proc);

    /*
    * 描述：获取进程的命令行信息(非kthread调用)
    * 参数：strPid 需要查询的进程pid; proc 用于保存结果的引用;
    * 返回值：错误码
    */
    CECode _ParseCmdlineFile(const char *strPid, PROCESS_INFO_T &proc);
    /*
    * 描述：获取进程的执行文件全路径信息(非kthread调用)
    * 参数：strPid 需要查询的进程pid; proc 用于保存结果的引用;
    * 返回值：错误码
    */
    CECode _ParseExeLinkFile(const char *strPid, PROCESS_INFO_T &proc);


    /*
    * 描述：初始化系统用户信息，结果保存到m_mapPwEnt
    * 参数：无
    * 返回值：无
    */
    void _InitPwEnt();
    /*
    * 描述：通过用户uid在m_mapPwEnt获取用户名信息
    * 参数：uid 需要查询的用户uid; proc 用于保存结果的引用;
    * 返回值：错误码
    */
    CECode _GetUserByUid(uint32_t uid, PROCESS_INFO_T &proc);

    /*
    * 描述：遍历/proc目录得到当前系统所有进程的信息
    * 参数：无
    * 返回值：错误码
    */
    CECode _ScanAllProc();

private:
    std::map<uint32_t, PROCESS_INFO_T> m_mapProcInfo;
    std::map<uint32_t, std::string> m_mapPwEnt;
    time_t m_nSysBootTime;
};
#endif //PROC_INFO_H
