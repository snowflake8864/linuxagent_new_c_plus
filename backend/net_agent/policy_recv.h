#ifndef BACKEND_NET_AGENT_POLICY_RECV_H_
#define BACKEND_NET_AGENT_POLICY_RECV_H_

#include <string>
#include <set>
#include "common/qh_thread/thread.h"
#include "osec_common/policy_type.hpp"
#include "osec_common/global_message.h"

class CEntClientNetAgent;

typedef void (*RUN_TASK_CALL)(void* param,TASK_TYPE type);

class CPolicyRecvWorker : public QH_THREAD::CThread {
  public:
    CPolicyRecvWorker() {
        m_all_task_type_ += NOTIFY_APPLY_RESULT;
        m_all_task_type_ += ",";
        m_all_task_type_ += NOTIFY_APPROVE_RESULT;
        m_all_task_type_ += ",";
        m_all_task_type_ += NOTIFY_CLIENT_LEVEL;
        m_bOnline =  false;
        m_sleep_time = 30;
    }
    ~CPolicyRecvWorker() {
        m_bOnline =  false;
    }

  public:
    static CPolicyRecvWorker* GetInstance()
    {
        static CPolicyRecvWorker mgr;
        return &mgr;
    }

    bool Init(CEntClientNetAgent* pNetAgent, RUN_TASK_CALL task);
    bool UnInit();
    bool Run();
    std::string get_token() { return m_strToken ;}
    int set_sleep_time(int sleep_time) { m_sleep_time = sleep_time; return 0;}
  private:
    void recvNewTask();
    void refreshPolicyInfo(const std::string& str_section, const std::string& str_key, int value);
    void parseRecvTask(const std::string& str_content);
    std::string GetServerAddrInfo();
  protected:
    virtual void* thread_function(void* param);

  private:
    QH_THREAD::CMutex m_mutex_net_info_;
    std::string m_server_ip_;
    std::string m_server_port_;
    std::string m_mid_;
    std::string m_all_task_type_;
    bool m_bOnline;
    std::string m_strToken;
    RUN_TASK_CALL m_callFun;
    CEntClientNetAgent* m_pNetAgent;
    int m_sleep_time;
public:
    BASE_ONLINE m_baseinfo;
};

#define CPOLICYRECVMGR (CPolicyRecvWorker::GetInstance())

#endif /* BACKEND_NET_AGENT_POLICY_RECV_H_ */
