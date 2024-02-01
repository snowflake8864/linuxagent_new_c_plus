#ifndef NETMGR_ENTCLIENT_REPORT_MGR_H_
#define NETMGR_ENTCLIENT_REPORT_MGR_H_

#include <string.h>
#include <string>
#include <list>
#include "common/ASFramework/ASBundle.h"
#include "common/qh_thread/thread.h"
#include "common/qh_thread/multi_thread.h"
#include "report_db_helper.h"

class CEntClientNetAgent;
class CNetReportMgr : public QH_THREAD::CMultiThread {
  public:
    CNetReportMgr() { m_inited_ = false; }
    ~CNetReportMgr() {
        UnInit();
    }

  public:
    bool Init(CEntClientNetAgent *pSocket);
    void UnInit();
    static CNetReportMgr* GetInstance() {
        static CNetReportMgr rmgr;
        return &rmgr;
    }

  public:
    int Report(const LOG_INFO& loginfo);

  private:
    void ReportSynData();
    bool SynReport(IASBundle* pData, bool& bErase);
    std::string CreateReportMsgUUID();

  protected:
    virtual void* thread_function(void* param);

  private:
    CEntClientNetAgent *m_pSock;
    volatile bool m_inited_;
    QH_THREAD::CMutex m_reportdata_locker_;
    std::list<LOG_INFO> m_reportdata_list_;
};

#define REPORTMGRPTR (CNetReportMgr::GetInstance())

#endif /* NETMGR_ENTCLIENT_REPORT_MGR_H_ */
