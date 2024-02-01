#ifndef NETMGR_ENTCLIENT_REPORT_MGR_H_
#define NETMGR_ENTCLIENT_REPORT_MGR_H_

#include <string.h>
#include <string>
#include <list>
#include "common/ASFramework/ASBundle.h"
#include "common/qh_thread/thread.h"
#include "common/qh_thread/multi_thread.h"
#include "netlog_mgr.h"

class CEntClientNetAgent;
class CNetlogMgr : public QH_THREAD::CMultiThread {
  public:
    CNetlogMgr() { m_inited_ = false; }
    ~CNetlogMgr() {
        UnInit();
    }

  public:
    bool Init();
    void UnInit();
    static CNetlogMgr* GetInstance() {
        static CNetlogMgr rmgr;
        return &rmgr;
    }

  public:
    int Report(IASBundle* pData);
    void SetAgentClient(CEntClientNetAgent *Agent);
    bool SaveData(std::string str_data);
  private:
    bool SynReport();
    std::string CreateReportMsgUUID();

  protected:
    virtual void* thread_function(void* param);

  private:
    volatile bool m_inited_;
    QH_THREAD::CMutex m_netlog_locker_;
    CEntClientNetAgent *m_pAgentClient;
};

#define CNETLOGMGR (CNetlogMgr::GetInstance())

#endif /* NETMGR_ENTCLIENT_REPORT_MGR_H_ */
