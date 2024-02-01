#ifndef BACKEND_NET_AGENT_NET_STATUS_H_
#define BACKEND_NET_AGENT_NET_STATUS_H_

#include <string>
#include "common/qh_thread/locker.hpp"
#include "common/openssl_thread_safe.h"


class IASBundle;

class CNetStatus {
  public:
    CNetStatus() {};
    ~CNetStatus(){};

  public:
    static CNetStatus* GetInstance() {
        static CNetStatus mgr;
        return &mgr;
    }
    bool Init();

  public:
    void RefreshServerIpPort(const std::string& server_ip, const std::string& server_port);
    void SetServerIPPORT(const std::string& str_server_ip, const std::string& str_server_port);
    void SetClientMID(const std::string& str_mid);
    void GetServerIPPORT(std::string& str_server_ip, std::string& str_server_port);
    
    bool PostDataUseURL(std::string strUrl, std::string& strNetOut, char * lpContent, int nContLen, long& nHttpCode, long dwWaitTimeOut = 10);
 
    bool GetDataUseURL(std::string strUrl, std::string& strNetOut, long& nHttpCode, long dwWaitTimeOut = 10);
    bool GetDataUseURL(std::string strUrl, IASBundle *pOut, long dwWaitTimeOut = 10);
      
    bool PostDataUseURL(std::string strToken, std::string file_path, std::string strUrl, std::string& strNetOut, char * lpContent, int nContLen, long& nHttpCode, long dwWaitTimeOut = 10);

    bool PostDataUseURL(std::string strToken, std::string strUrl, std::string& strNetOut, char * lpContent, int nContLen, long& nHttpCode, long dwWaitTimeOut = 10);
    bool PostDataUseURL(std::string strToken, std::string strUrl, IASBundle *pOut, char * lpContent, int nContLen, long dwWaitTimeOut = 10);
    bool PostDataFile(std::string strToken, std::string strUrl, std::string& strNetOut, std::string file, std::string hash, long& nHttpCode, long dwWaitTimeOut = 10 );
    bool GenServerUri(const std::string& strUrl, std::string& strUri);
    // TODO <--- ---> cause server cannot set s3 server ip | add tmp
    std::string GetServerIP() { return m_server_ip_; }

  private:
    QH_THREAD::CMutex m_mutex_;
    std::string m_server_ip_;
    std::string m_server_port_;
    std::string m_client_mid_;
    openssl_thread_safe::SmartHandle m_openssl_thread_safe_smart_handle_;
};

int down_file(const char* url, const char* down_file_name);

#define CNETSTATUS (CNetStatus::GetInstance())

#endif /* BACKEND_NET_AGENT_NET_STATUS_H_ */
