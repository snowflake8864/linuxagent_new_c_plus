#ifndef COPENPORTCACHE_MGR_H_
#define COPENPORTCACHE_MGR_H_

#include <string.h>
#include <string>
#include <list>
#include "common/ASFramework/ASBundle.h"
#include "common/qh_thread/thread.h"
#include "common/qh_thread/multi_thread.h"
#if 0
struct COPENPORT_CACHE {
    std::vector<pOpenPort> ;
    int level;
};
#endif
class CThreadOpenPort : public QH_THREAD::CMultiThread {
  public:
    CThreadOpenPort() { m_inited_ = false; }
    ~CThreadOpenPort() {
        UnInit();
    }

  public:
    bool Init();
    void UnInit();
    static CThreadOpenPort* GetInstance() {
        static CThreadOpenPort rmgr;
        return &rmgr;
    }

  public:
    int  AddOpenPortCache(std::vector<pOpenPort>& infoVec);

  protected:
    virtual void* thread_function(void* param);

  private:
    volatile bool m_inited_;
    QH_THREAD::CMutex m_cache_locker_;
    std::list<std::vector<pOpenPort> > m_cache_list_;
};

#define OSEC_OPENPORT_CACHE (CThreadOpenPort::GetInstance())

#endif /* NETMGR_ENTCLIENT_REPORT_MGR_H_ */
