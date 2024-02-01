#ifndef CPROCESSCACHE_MGR_H_
#define CPROCESSCACHE_MGR_H_

#include <string.h>
#include <string>
#include <list>
#include "common/ASFramework/ASBundle.h"
#include "common/qh_thread/thread.h"
#include "common/qh_thread/multi_thread.h"

struct CPROCES_CACHE {
    struct av_process_info proc_info;
    std::string hash;
    int level;
    std::string edr_process_p_aram;
    std::string edr_process_pp_aram;
};

class CThreadProcess : public QH_THREAD::CMultiThread {
  public:
    CThreadProcess() { m_inited_ = false; }
    ~CThreadProcess() {
        UnInit();
    }

  public:
    bool Init();
    void UnInit();
    static CThreadProcess* GetInstance() {
        static CThreadProcess rmgr;
        return &rmgr;
    }

  public:
    int  AddProcessCache(struct av_process_info& info);

  protected:
    virtual void* thread_function(void* param);

  private:
    volatile bool m_inited_;
    QH_THREAD::CMutex m_cache_locker_;
    std::list<struct av_process_info> m_cache_list_;
};

#define OSEC_PROCES_CACHE (CThreadProcess::GetInstance())

#endif /* NETMGR_ENTCLIENT_REPORT_MGR_H_ */
