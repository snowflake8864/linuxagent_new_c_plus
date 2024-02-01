#ifndef CPU_LIMIT_PROCESSEX_H
#define CPU_LIMIT_PROCESSEX_H
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>

#define ALFA 0.08

//USER_HZ detection, from openssl code
#ifndef HZ
# if defined(_SC_CLK_TCK) \
     && (!defined(OPENSSL_SYS_VMS) || __CTRL_VER >= 70000000)
#  define HZ ((double)sysconf(_SC_CLK_TCK))
# else
#  ifndef CLK_TCK
#   ifndef _BSD_CLK_TCK_ /* FreeBSD hack */
#    define HZ  100.0
#   else /* _BSD_CLK_TCK_ */
#    define HZ ((double)_BSD_CLK_TCK_)
#   endif
#  else /* CLK_TCK */
#   define HZ ((double)CLK_TCK)
#  endif
# endif
#endif

struct process {
    pid_t pid;
    int iStartTime;
    int iMember;
    int iLastJiffies;
    struct timeval tLastSample;
    double dCpuUsage;
    int iIsZombie;
    char cCommand[PATH_MAX + 1];

    char cStatFile[20];
    char cBuffer[1024];
};

#include "actor.h"

class Observer {
  protected:
    virtual ~Observer() = 0;
  public:
    virtual void update(double dParam) = 0;
};

class ProcessEx : public IActorCallBack {
  public:
    ProcessEx();
    ~ProcessEx();

  private:
    struct process* m_pProc;
    Observer* m_pObserver;

  private:
    int getInfo(struct process* pProc, pid_t pid);
    int getStartTime(pid_t pid);
    int getJiffies();
    unsigned long timeDiff(const struct timeval* t1, const struct timeval* t2);
    int calcateProcessCpuUsage();

  public:
    int init(pid_t pid);
    int close();

    virtual void OnActivate(Actor* pActor);

    void registerObserver(Observer* pObj);
    void notifyObserver(double dParam);

  public:
    Actor m_worker;
};

#endif /* CPU_LIMIT_PROCESSEX_H */
