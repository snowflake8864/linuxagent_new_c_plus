#include <utmp.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "sshguard.h"
#include "common/log/log.h"
#include "common/json/cJSON.h"
#include "common/utils/string_utils.hpp"
#include "common/ASFramework/util/ASJsonWrapper.h"
#include "common/utils/time_utils.hpp"

#define SSHBLOCKCONF "sshblock.conf"

bool CSshGuard::date2timestamp(std::string &strtime, time_t &timestamp) {
    struct tm tm;
    struct tm tm2;
    memset(&tm, 0, sizeof(tm));
    //"2022-01-12 18:23:31"
    if(strptime(strtime.c_str(), "%Y-%m-%d %H:%M:%S", &tm)) {
        timestamp = mktime(&tm);
        return true;
    }

    //"Jul 28 16:17:44"
    if(!strptime(strtime.c_str(), "%b %d %H:%M:%S", &tm)) {
        return false;
    }
    time_t current_time = time(NULL);
    localtime_r(&current_time, &tm2);
    //跨年
    if(tm2.tm_mon < tm.tm_mon) {
        tm2.tm_year -= 1;
    }
    tm2.tm_mon  = tm.tm_mon;
    tm2.tm_mday = tm.tm_mday;
    tm2.tm_hour = tm.tm_hour;
    tm2.tm_min  = tm.tm_min;
    tm2.tm_sec  = tm.tm_sec;
    timestamp = mktime(&tm2);
    if(-1==timestamp) {
        return false;
    }
    return true;
}

CSshGuard::CSshGuard():m_is_init(false) {

    memset(&m_sshlogfile, 0, sizeof(m_sshlogfile));
    const char *secure_log[]={
        //Redhat or Fedora Core
        //"/var/log/secure",
        //Debian and Ubuntu Mandrake, FreeBSD or OpenBSD
        "/var/log/auth.log",
        "/var/log/btmp",
        //rocky
        "/var/log/auth",
        //Mac OS X (v10.3 or earlier)
        //"/private/var/log/system.log",
        //Mac OS X (v10.4 or greater -
        //also refer to:   http://www.denyhosts.net/faq.html#macos
        //"/private/var/log/asl.log",
        //SuSE
        //"/var/log/messages"
    };
    size_t  m=0,n;
RETRY:
    for(n=0;n<sizeof(secure_log)/sizeof(char *);++n) {
        if(access(secure_log[n],F_OK)==0) {
            m_sshlogfile.SshLogFile=secure_log[n];
            break;
        }
    }
    if(n==sizeof(secure_log)/sizeof(char *)) {
        if(++m < 10) {
            usleep(250000);
            goto RETRY;
        }
    }
    OpenSshLog(true);
    char localhostname[256]={0};
    gethostname(localhostname, sizeof(localhostname));
    m_hostname=localhostname;
}

CSshGuard::~CSshGuard() {
    Uninit();
}

bool CSshGuard::OpenSshLog(bool bfirst) {
    if(m_sshlogfile.fp) {
        return true;
    }
    if(!m_sshlogfile.SshLogFile) {
        return false;
    }
    if ((m_sshlogfile.fp = fopen(m_sshlogfile.SshLogFile, "r")) == NULL) {
        LOG_ERROR("open file：%s error", m_sshlogfile.SshLogFile);
        return false;
    }

    if (fstat(fileno(m_sshlogfile.fp), &m_sshlogfile.st) < 0) {
        fclose(m_sshlogfile.fp);
        m_sshlogfile.fp = NULL;
        LOG_ERROR("fstat file：%s error", m_sshlogfile.SshLogFile);
        return false;
    }
    memcpy(&m_sshlogfile.sb2,&m_sshlogfile.st, sizeof(struct stat));
    // if(bfirst) {
    //     fseeko(m_sshlogfile.fp, m_sshlogfile.st.st_size, SEEK_SET);
    // }
    return true;
}

bool CSshGuard::CloseSshLog() {
    int ret;
    if(!m_sshlogfile.fp) {
        return true;
    }
    ret = fclose(m_sshlogfile.fp);
    m_sshlogfile.fp = NULL;
    return 0==ret;
}

bool CSshGuard::SshLogFileStat() {
    if(-1==stat(m_sshlogfile.SshLogFile, &m_sshlogfile.sb2)) {
        LOG_INFO("SshLogFileStat stat:%s error", m_sshlogfile.SshLogFile);
        return false;
    }
    return true;
}

bool CSshGuard::IsNewSshLogFile() {

    if (m_sshlogfile.sb2.st_ino != m_sshlogfile.st.st_ino ||
        m_sshlogfile.sb2.st_dev != m_sshlogfile.st.st_dev ||
        m_sshlogfile.sb2.st_nlink == 0 ||
        m_sshlogfile.sb2.st_mtime > m_sshlogfile.st.st_mtime) {
        return true;
    }
    return false;
}

int CSshGuard::Readauthlog() {
    char buf[1024];
    size_t bufLen;
    while(fgets(buf, sizeof(buf), m_sshlogfile.fp)) {
        LOG_INFO("Readauthlog read bt mptp ssh.....");
        bufLen = strlen(buf);
        if('\n' == buf[bufLen -1]) {
            struct sshInfo sshinfo;
            if(ParseOneLine(buf,sshinfo)) {
                LOG_INFO("ssh ip:%s", sshinfo.ip.c_str());
                AddSshLoginInfo(sshinfo);
            }
        }
    }
    if (ferror(m_sshlogfile.fp)) {
        fclose(m_sshlogfile.fp);
        m_sshlogfile.fp = NULL;
        return 0;
    }
    if(ftello(m_sshlogfile.fp) > m_sshlogfile.st.st_size) {
        fstat(fileno(m_sshlogfile.fp), &m_sshlogfile.st);
    }
    clearerr(m_sshlogfile.fp);
    return 1;
}
std::string CSshGuard::getipaddr(const struct utmp * u) {
    char buf[INET6_ADDRSTRLEN + 1]={0};
    char buf_ipv6[INET6_ADDRSTRLEN];
    int32_t ut_addr_v6[4];      /* IP address of the remote host */

    memcpy(&ut_addr_v6, &u->ut_addr_v6, sizeof(ut_addr_v6));
    if (IN6_IS_ADDR_V4MAPPED(&ut_addr_v6)) {
            /* map back */
            ut_addr_v6[0] = ut_addr_v6[3];
            ut_addr_v6[1] = 0;
            ut_addr_v6[2] = 0;
            ut_addr_v6[3] = 0;
    }
    if (ut_addr_v6[1] || ut_addr_v6[2] || ut_addr_v6[3]) {
            /* IPv6 */
            if (!inet_ntop(AF_INET6, &ut_addr_v6, buf_ipv6, sizeof(buf_ipv6))) {
                    strcpy(buf, ""); /* invalid address, clean the buffer */
            } else {
                    strncpy(buf, buf_ipv6, INET6_ADDRSTRLEN); /* address valid, copy to buffer */
            }
    } else {
            /* IPv4 */
            if (!(ut_addr_v6[0] && inet_ntop(AF_INET, &ut_addr_v6[0], buf, sizeof(buf)))) {
                    strcpy(buf, ""); /* invalid address, clean the buffer */
            }
    }
    return std::string(buf);
}

int CSshGuard::Readbtmplog() {
    struct utmp cr;

    size_t reclen = sizeof(struct utmp);

    while (fread(&cr, reclen, 1, m_sshlogfile.fp)) {
        // LOG_INFO("begin read bt mptp ssh.....");
        struct sshInfo sshinfo;
		if (!(strstr(cr.ut_line, "ssh") || strstr(cr.ut_line, "SSH"))) {
            LOG_INFO("aaaaaaaaaa....");
            continue;
        }
        sshinfo.ip = getipaddr(&cr);
        if(sshinfo.ip.empty()) {
            LOG_INFO("bbbbbbbbbbb....");
            continue;
        }
        sshinfo.time = cr.ut_xtime;
        sshinfo.user = cr.ut_user;
        sshinfo.result = 1;
        sshinfo.ip = cr.ut_host;
        //sshinfo.port =  
        in_addr host_ipaddr;
        memcpy(&host_ipaddr, &cr.ut_addr_v6, 4);
        sshinfo.ip = inet_ntoa(host_ipaddr);
        LOG_INFO("read bt mptp ssh host:%s .....", sshinfo.ip.c_str());
        AddSshLoginInfo(sshinfo);
	} 
    
    if (ferror(m_sshlogfile.fp)) {
        fclose(m_sshlogfile.fp);
        m_sshlogfile.fp = NULL;
        return 0;
    }
    if(ftello(m_sshlogfile.fp) > m_sshlogfile.st.st_size) {
        fstat(fileno(m_sshlogfile.fp), &m_sshlogfile.st);
    }
    clearerr(m_sshlogfile.fp);
    return 1;
}

int CSshGuard::ReadSshlog()
{
    if(!m_sshlogfile.fp) {
        LOG_INFO("OpenSshLog fp NULL");
        return 0;
    }
    if(m_sshlogfile.SshLogFile && 
        !strcmp(m_sshlogfile.SshLogFile,"/var/log/btmp")) 
    {
         LOG_INFO("1111111111");
        return Readbtmplog();
    } else {
         LOG_INFO("22222222222");
        return Readauthlog();
    }
    return 0;
}

void *CSshGuard::SshLogFollowThread(void* para)
{
    LOG_INFO("setup into the ssh log follow thread");
    QH_THREAD::CWorkerThread* cur_thread_p = static_cast<QH_THREAD::CWorkerThread*>(para);
    while(!cur_thread_p->IsQuit()) {
        bool rc = false;
        LOG_INFO("begin open sshlog");
        if(!OpenSshLog(true)) {
            usleep(250000);
            LOG_INFO("OpenSshLog continue.....");
            continue;
        }
        //rc = SshLogFileStat();
        LOG_INFO("SshLogFileStat stat:%s", m_sshlogfile.SshLogFile);
        ReadSshlog();
        if(rc && IsNewSshLogFile()) {
            ReadSshlog();
            CloseSshLog();
            LOG_INFO("IsNewSshLogFile  rc continue.....");
            continue;
        }
        (void) sleep(5);
        LOG_INFO("end open sshlog");
    }
    CloseSshLog();
    LOG_INFO("setup out of the ssh log follow thread");
    return NULL;
}

void CSshGuard::AddSshLoginInfo(struct sshInfo &sshinfo) {
    // std::map<std::string, struct ssh_brute_force>::iterator it;
    // QH_THREAD::CMutexManualLocker Lck(&m_mutex_events);
    // Lck.lock();
    // it = m_ssh_attack.find(sshinfo.ip);
    // //没有ssh登录失败记录
    // if(it == m_ssh_attack.end()) {
    //     //只处理失败情况
    //     if(0 !=sshinfo.result ) {
    //         struct ssh_brute_force sshbf;
    //         sshbf.deny = false;
    //         sshbf.passseconds = 0;
    //         sshbf.denyseconds  = 0;
    //         sshbf.lasttime = sshinfo.time;
    //         sshbf.vtime.push_back(sshinfo.time);
    //         m_ssh_attack[sshinfo.ip]=sshbf;
    //     }
    //     Lck.unlock();
    //     return;
    // } else {
    //     struct ssh_brute_force &sshbf = it->second;
    //     //成功登录清除之前的失败记录
    //     if(0==sshinfo.result) {
    //         sshbf.vtime.clear();
    //         sshbf.denyseconds =0;
    //     } else {
    //         //失败登录追加记录，也就是登录失败时间戳
    //         sshbf.lasttime = sshinfo.time;
    //         sshbf.passseconds = 0;
    //         sshbf.vtime.push_back(sshbf.lasttime);
    //     }
    //     Lck.unlock();
    // }
}

bool CSshGuard::ParseOneLine(const char *line, struct sshInfo &item)
{
    std::vector<std::string> key_values;
    std::string strTemp = line;
    size_t  index = 0;
    string_utils::Split(key_values, line, " ");
    if (key_values.size() < 12)
        return false;
    //ssh连接类型
    if (key_values[4].find("sshd") == std::string::npos && key_values[3].find("sshd") == std::string::npos)
        return false;
    //密码不对
    //Aug  8 01:26:23 localhost sshd[12413]: Failed password for invalid user test from 172.24.51.104 port 32828 ssh2
    //Dec 15 14:47:31 arm01 sshd[117902]: Failed password for test from 172.24.51.39 port 38158 ssh2
    //2022-01-12 18:23:31 zpy-PC sshd[1255]:  Failed password for zpy from 127.0.0.1 port 50602 ssh2
    if (strTemp.find("Failed password for ") != std::string::npos && key_values.size() >= 13) {
        if ("from" == key_values[11]) { index  = 11; item.result = 2;}
        else if("from" == key_values[9]) { index = 9;item.result = 1;}
        else if("from" == key_values[8]) { index = 8;item.result = 3;}
    }
#if 0
    //用户名不对
    Failed none for invalid user testtest1 from 127.0.0.1 port 33406 ssh2
    //Dec 15 14:47:44 arm01 sshd[117950]: Invalid user test21 from 172.24.51.39 port 38168
    else if (strTemp.find("Invalid user ") != std::string::npos) {
        if("from" == key_values[8]) { index = 8; item.result = 1;}
    }
#endif
    //登录成功
    //Dec 15 11:09:00 arm01 sshd[101140]: Accepted password for root from 172.24.51.39 port 34306 ssh2
    //2022-01-13 09:51:04 zpy-PC sshd[31172]:  Accepted password for zpy from 127.0.0.1 port 36190 ssh2
    else if (strTemp.find("Accepted password for ") != std::string::npos) {
        if("from" == key_values[9]) { index = 9; item.result = 0;}
        else if ("from" == key_values[8]) { index = 8; item.result = 0;}
    }

    if(0==index) {
        return false;
    } 
    item.ip   = key_values[index + 1];
    item.user = key_values[index - 1];
    item.port = atoi(key_values[index + 3].c_str());
    std::string strTime;
    if(index == 8) {
        strTime = key_values[0] + " " + key_values[1];
    } else {
        strTime = key_values[0] + " " + key_values[1] + " " + key_values[2];
    }
    return date2timestamp(strTime,item.time);
}

void CSshGuard::Init(size_t ssh_denyhours) {
    StartSshLogFollowThread();
}

void CSshGuard::Uninit() {
    StopSshLogFollowThread();
}

void CSshGuard::StartSshLogFollowThread() {
    m_logfollow_thread.SetThreadFunc(std::tr1::bind(&CSshGuard::SshLogFollowThread, this, std::tr1::placeholders::_1));
    m_logfollow_thread.Run(&m_logfollow_thread);
}

void CSshGuard::StopSshLogFollowThread() {
    m_logfollow_thread.Quit();
    m_logfollow_thread.Join();
}