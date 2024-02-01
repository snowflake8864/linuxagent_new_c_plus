#ifndef UTILS_NET_UTILS_H_
#define UTILS_NET_UTILS_H_

#include <vector>
#include <memory>
#include <string>
#include "curl/curl.h"

struct HttpHeaderInfo {
    std::string UserName;
    std::string Password;
    std::string Date;
    std::string ContentLength;
    std::string ContentType;
    std::string Connection;
    std::string Host;
    std::string Key;
};


bool downfile(const char *file_save_path, const char* url_path);
class CNetCurl
{
    // Post form.
    struct FormParam {
        enum Type {
            DEFAULT = 0,
            CONTENT,
            FILE,
        } type;
        std::string name;
        std::string content;        // NAME_CONTENT.
        std::string file;           // FILE.
    };
  public:
    CNetCurl();
    ~CNetCurl() { UnInit(); }

  public:
    bool Init();
    bool UnInit();
    void SetUrl(const char *url);

    // Get.
    bool Get(int timeout = 60, int conntime = 60);
    bool Get(const char *filepath, const struct HttpHeaderInfo &header_info);

    // Put.
    bool Put(const char *filepath, const struct HttpHeaderInfo &header_info);

    // Post.
    void AddForm(const char *name, const char *content);
    void AddFile(const char *name, const char *fullpath);
    bool Post(int timeout = 60);
    bool Post(std::string &token,int timeout, const char* lpbuf, int nlen, int conntime = 60);
    bool Post(std::string &token, std::string &file_path,int timeout, const char* lpbuf, int nlen, int conntime = 60);
   
    bool Post(int timeout,const char* lpbuf, int nlen, int conntime = 60);
    // Delete.
    bool Delete(const struct HttpHeaderInfo &header_info, int timeout = 10 * 60, int conntime = 60);
    bool Postfile(const std::string &strToken,const std::string &file, std::string &hash, int timeout,int conntime = 60);
    // Control.
    void Stop();

    // Status.
    bool IsStopped();
    bool GetResponse(void *res, int *len);
    std::string GetStrResponse();
    bool SaveAsFile(const char *fullpath);
    bool GetRespCode(long& respcode);

    static size_t read_function(char *bufptr, size_t size, size_t nitems, void *userp);
    static size_t read_function_put_file(char *bufptr, size_t size, size_t nitems, void *userp);
    static size_t write_function(void *buffer, size_t size, size_t nmemb, void *userp);
    static size_t write_function_get_file(void *buffer, size_t size, size_t nmemb, void *userp);
    static int progress_function(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);

  private:
    // logic.
    bool requestStop();
    bool polling(int timeout);

  private:
    // data.
    CURL *m_easy_handle_;
    CURLM *m_multi_handle_;
    // Url.
    std::string m_url_;
    // Response.
    void *m_recv_;
    int m_recv_len_;

    std::vector<FormParam> m_form_;

    volatile long m_request_stop_;
    bool m_is_stopped_;
};

#endif /* UTILS_NET_UTILS_H_ */
