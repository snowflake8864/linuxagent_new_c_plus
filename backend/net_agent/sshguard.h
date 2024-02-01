#ifndef SSH_GUARD_H_
#define SSH_GUARD_H_
#include "common/qh_thread/thread.h"
#include <string>
#include <vector>

#define ERRORLOGINTHRESHOLD   (5)
#define ERRORLOGINKEEPSECONDS (10)
#define DENYSECONDS           (43200) //12小时

struct sshlogfile{
    FILE    *fp;                //ssh log 
    const   char *SshLogFile;   //ssh log path
    struct  stat st;            //
    struct  stat sb2;           //stat log path
};

struct sshInfo {
    std::string ip;
    std::string user;
    time_t time;
    int port;
    int result;
};

struct ssh_brute_force {
    bool   deny;         //拒绝状态
    size_t passseconds;  //基于lasttime，流逝时长
    size_t denyseconds;  //拒绝ssh访问时长
    time_t lasttime;     //最后登录失败的时间戳
    std::vector<time_t> vtime; //登录失败的时间戳
};

class CSshGuard {

public:
    CSshGuard();
    ~CSshGuard();
    void Init(size_t ssh_denyhours);
    void Uninit();

private:

    bool OpenSshLog(bool bfirst=false);
    int  ReadSshlog();
    int  Readbtmplog();
    int  Readauthlog();
    bool SshLogFileStat();
    bool IsNewSshLogFile();
    bool CloseSshLog();
    void AddSshLoginInfo(struct sshInfo &sshinfo);
    std::string getipaddr(const struct utmp *u);
    bool date2timestamp(std::string &strtime, time_t &timestamp);
    bool ParseOneLine(const char *line,struct sshInfo &sshinfo);
    void *SshLogFollowThread(void* para);
    void StartSshLogFollowThread();
    void StopSshLogFollowThread();

private:
    volatile bool m_is_init;
    std::string m_hostname;
    struct sshlogfile m_sshlogfile;
    QH_THREAD::CMutex m_mutex_events;
    QH_THREAD::CWorkerThread m_guard_thread;
    QH_THREAD::CWorkerThread m_logfollow_thread;
    //std::map<std::string, struct ssh_brute_force> m_ssh_attack;
};
#endif /* SSH_GUARD_H_ */
