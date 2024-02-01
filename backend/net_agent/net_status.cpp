#include "backend/net_agent/net_status.h"
#include <sstream>
#include "common/log/log.h"
#include "common/ASFramework/ASBundleImpl.hpp"
#include "common/ini_parser.h"
#include "osec_common/osec_pathmanager.h"
#include "osec_common/global_config.hpp"
#include "common/utils/file_utils.h"
#include "curl/curl.h"
#include "backend/net_agent/report_data_control.hpp"
#include "common/utils/net_utils.h"

bool CNetStatus::Init() {
    INIParser parser;
    std::string net_info_path = PathManager::GetClientServerNetInfoPath();
    if (!file_utils::IsExist(net_info_path)) {
        LOG_ERROR("local socket config file[%s] is not exist.", net_info_path.c_str());
    }
    if(!parser.ReadINI(net_info_path)) {
        LOG_ERROR("parse net info path[%s] failed.", net_info_path.c_str());
    } else {
        std::string str_mid = parser.GetValue(SECTION_CLIENTINFO, KEY_CLIENT_MID);
        std::string str_server_ip = parser.GetValue(SECTION_SERVERINFO, KEY_SERVER_IP);
        std::string str_server_port = parser.GetValue(SECTION_SERVERINFO, KEY_SERVER_PORT);
        QH_THREAD::CMutexAutoLocker Lck(&m_mutex_);
        m_client_mid_ = str_mid;
        m_server_ip_ = str_server_ip;
        m_server_port_ = str_server_port;
    }

    m_openssl_thread_safe_smart_handle_ = openssl_thread_safe::GetThreadSafeSmartHandle();
    CURLcode nRet = curl_global_init(CURL_GLOBAL_ALL);
    if (CURLE_OK != nRet) {
        LOG_ERROR("net agent init curl failed.");
        return false;
    }
    return true;
}

void CNetStatus::RefreshServerIpPort(const std::string& server_ip, const std::string& server_port) {
    bool bchanged = false;
    {
        QH_THREAD::CMutexAutoLocker Lck(&m_mutex_);
        if (m_server_ip_ != server_ip || m_server_port_ != server_port) {
            bchanged = true;
        }
        m_server_ip_ = server_ip;
        m_server_port_ = server_port;
    }
    if (true == bchanged) {
        SetServerIPPORT(server_ip, server_port);
    }
}

void CNetStatus::SetServerIPPORT(const std::string& str_server_ip, const std::string& str_server_port) {
    INIParser parser;
    std::string net_info_path = PathManager::GetClientServerNetInfoPath();
    if (!parser.ReadINI(net_info_path)) {
        LOG_ERROR("parse net info path[%s] failed.", net_info_path.c_str());
        return;
    }
    parser.SetValue(SECTION_SERVERINFO, KEY_SERVER_IP, str_server_ip);
    parser.SetValue(SECTION_SERVERINFO, KEY_SERVER_PORT, str_server_port);
    parser.WriteINI(net_info_path);
}

void CNetStatus::SetClientMID(const std::string& str_mid) {
    INIParser parser;
    std::string net_info_path = PathManager::GetClientServerNetInfoPath();
    if (!parser.ReadINI(net_info_path)) {
        LOG_ERROR("parse net info path[%s] failed.", net_info_path.c_str());
        return;
    }
    parser.SetValue(SECTION_CLIENTINFO, KEY_CLIENT_MID, str_mid);
    parser.WriteINI(net_info_path);
}

void CNetStatus::GetServerIPPORT(std::string& str_server_ip, std::string& str_server_port) {
    INIParser parser;
    std::string net_info_path = PathManager::GetClientServerNetInfoPath();
    if (!parser.ReadINI(net_info_path)) {
        LOG_ERROR("parse net info path[%s] failed.", net_info_path.c_str());
        return;
    }
    str_server_ip   = parser.GetValue(SECTION_SERVERINFO, KEY_SERVER_IP);
    str_server_port = parser.GetValue(SECTION_SERVERINFO, KEY_SERVER_PORT);
}

bool CNetStatus::GetDataUseURL(std::string strUrl, std::string& strNetOut, long& nHttpCode, long dwWaitTimeOut) {
    CNetCurl net_curl;
    if (!net_curl.Init()) {
        return false;
    }
    net_curl.SetUrl(strUrl.c_str());
    bool httpRtn = net_curl.Get(dwWaitTimeOut);

    if (httpRtn) {
        net_curl.GetRespCode(nHttpCode);
        strNetOut = net_curl.GetStrResponse();
    }

    return httpRtn;
}

bool CNetStatus::GetDataUseURL(std::string strUrl, IASBundle *pOut, long dwWaitTimeOut) {
    CNetCurl net_curl;
    if (!net_curl.Init()) {
        return false;
    }
    net_curl.SetUrl(strUrl.c_str());
    bool httpRtn = net_curl.Get(dwWaitTimeOut);

    do {
        long dwHttpCode = 0;
        net_curl.GetRespCode(dwHttpCode);
        pOut->putInt(ReportKeyHttpCode, dwHttpCode);
        if(!httpRtn)
            break;

        int nlen = 0;
        bool bRtn = net_curl.GetResponse(NULL, &nlen);
        if(0 == nlen)
            break;

        char* lpBuf = new (std::nothrow) char[nlen];
        if(NULL ==lpBuf)
            break;

        bRtn = net_curl.GetResponse(lpBuf, &nlen);

        if (!bRtn || 0 == nlen) {
            delete [] lpBuf;
            break;
        }
        pOut->putBinary(ReportKeyContent, (unsigned char *)lpBuf, nlen);
        delete [] lpBuf;
    } while(false);
    return true;
}

bool CNetStatus::PostDataUseURL(std::string strToken,std::string file_path, std::string strUrl, std::string& strNetOut, char * lpContent, int nContLen, long& nHttpCode, long dwWaitTimeOut) {
    CNetCurl net_curl;
    if (!net_curl.Init()) {
        return false;
    }
    net_curl.SetUrl(strUrl.c_str());
    bool httpRtn = net_curl.Post(strToken,file_path, dwWaitTimeOut, lpContent, nContLen);

    if (httpRtn) {
        net_curl.GetRespCode(nHttpCode);
        strNetOut = net_curl.GetStrResponse();
    }

    return httpRtn;
}

bool CNetStatus::PostDataFile(std::string strToken, std::string strUrl, std::string& strNetOut, std::string file, std::string hash, long& nHttpCode, long dwWaitTimeOut) {
    CNetCurl net_curl;
    if (!net_curl.Init()) {
        return false;
    }
    net_curl.SetUrl(strUrl.c_str());
	bool httpRtn =false; 
	httpRtn = net_curl.Postfile(strToken,file, hash, (int)dwWaitTimeOut);
    if (httpRtn) {
	    net_curl.GetRespCode(nHttpCode);
	    strNetOut = net_curl.GetStrResponse();
    }

    return httpRtn;
}

bool CNetStatus::PostDataUseURL(std::string strToken, std::string strUrl, std::string& strNetOut, char * lpContent, int nContLen, long& nHttpCode, long dwWaitTimeOut) {
	CNetCurl net_curl;
	if (!net_curl.Init()) {
		return false;
	}
	net_curl.SetUrl(strUrl.c_str());
	bool httpRtn = net_curl.Post(strToken,dwWaitTimeOut, lpContent, nContLen);

	if (httpRtn) {
		net_curl.GetRespCode(nHttpCode);
		strNetOut = net_curl.GetStrResponse();
	}

	return httpRtn;
}


bool CNetStatus::PostDataUseURL(std::string strUrl, std::string& strNetOut, char * lpContent, int nContLen, long& nHttpCode, long dwWaitTimeOut) {
	CNetCurl net_curl;
	if (!net_curl.Init()) {
		return false;
	}
	net_curl.SetUrl(strUrl.c_str());
	bool httpRtn = net_curl.Post(dwWaitTimeOut, lpContent, nContLen);

	if (httpRtn) {
		net_curl.GetRespCode(nHttpCode);
		strNetOut = net_curl.GetStrResponse();
	}

	return httpRtn;
}

bool CNetStatus::PostDataUseURL(std::string strToken,std::string strUrl, IASBundle *pOut, char * lpContent, int nContLen, long dwWaitTimeOut) {
	CNetCurl net_curl;
	if (!net_curl.Init()) {
		return false;
	}
	net_curl.SetUrl(strUrl.c_str());
	bool httpRtn = net_curl.Post(strToken, dwWaitTimeOut, lpContent, nContLen);

	do {
		long dwHttpCode = 0;
		net_curl.GetRespCode(dwHttpCode);
		pOut->putInt(ReportKeyHttpCode, dwHttpCode);
		if(!httpRtn)
			break;

		int nlen = 0;
		bool bRtn = net_curl.GetResponse(NULL, &nlen);
		if(0 == nlen)
			break;

		char* lpBuf = new (std::nothrow) char[nlen];
		if(NULL ==lpBuf)
			break;

		bRtn = net_curl.GetResponse(lpBuf, &nlen);

		if (!bRtn || 0 == nlen) {
			delete [] lpBuf;
			break;
		}
		pOut->putBinary(ReportKeyContent, (unsigned char *)lpBuf, nlen);
		delete [] lpBuf;
	} while(false);
	return true;
}
static bool localIsIPv6 = false;
static bool isIPv6(const std::string& ip) {  
    return (ip.find(':') != std::string::npos);  
}


bool CNetStatus::GenServerUri(const std::string& strUrl, std::string& strUri) {
	if (m_server_ip_.empty() || m_server_port_.empty() || m_client_mid_.empty()) {
		std::string net_info_path = PathManager::GetClientServerNetInfoPath();
		if (!file_utils::IsExist(net_info_path)) {
			LOG_ERROR("local socket config file[%s] is not exist.", net_info_path.c_str());
		}
		INIParser parser;
		if(!parser.ReadINI(net_info_path)) {
			LOG_ERROR("GenServerUri:parse net info path[%s] failed.", net_info_path.c_str());
		} else {
			std::string str_mid = parser.GetValue(SECTION_CLIENTINFO, KEY_CLIENT_MID);
			std::string str_server_ip = parser.GetValue(SECTION_SERVERINFO, KEY_SERVER_IP);
			std::string str_server_port = parser.GetValue(SECTION_SERVERINFO, KEY_SERVER_PORT);
			QH_THREAD::CMutexAutoLocker Lck(&m_mutex_);
			m_client_mid_ = str_mid;
			m_server_ip_ = str_server_ip;
			m_server_port_ = str_server_port;
		}
	}
    localIsIPv6 = isIPv6(m_server_ip_);
	QH_THREAD::CMutexAutoLocker Lck(&m_mutex_);
	std::stringstream utstream;
	utstream << m_server_ip_;
//    if (localIsIPv6) {
//	    utstream << "]";
//    }

	utstream << ":";
	utstream << m_server_port_;
	utstream << "/";
	utstream << strUrl;
	//utstream << "?uid=";
	//utstream << m_client_mid_;
	strUri = utstream.str();
	//LOG_INFO("strUri = %s", strUri.c_str());
	return true;
}

static size_t process_data(void *buffer, size_t size, size_t nmemb, std::string& user_p)
{	
	user_p = (char*)buffer;

	return nmemb;
}
static const int FILE_EXIST = 200;
int down_file(const char* url, const char* down_file_name)
{
	// 初始化libcurl
	CURLcode return_code;
	return_code = curl_global_init(CURL_GLOBAL_ALL);
	if (CURLE_OK != return_code)
	{
		printf("init libcurl failed.\n");
		curl_global_cleanup();
		return -1;
	}

	// 获取easy handle
	CURL *easy_handle = curl_easy_init();
	if (NULL == easy_handle)
	{		
		printf("get a easy handle failed..\n");
		curl_easy_cleanup(easy_handle);
		curl_global_cleanup();
		return -1;
	}

	// 设置easy handle属性
	return_code = curl_easy_setopt(easy_handle, CURLOPT_URL, url);

	//设置回调函数
	return_code = curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, &process_data);

	//回调函数的额外参数
	std::string connectx;
	return_code = curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, &connectx);

	// 执行数据请求
	return_code = curl_easy_perform(easy_handle);	

	//判断获取响应的http地址是否存在,若存在则返回200,400以上则为不存在,一般不存在为404错误
	int retcode = 0;
	return_code = curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE , &retcode);  
	if (CURLE_OK == return_code && FILE_EXIST == retcode)
	{
		double length = 0;
		return_code = curl_easy_getinfo(easy_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD , &length); 
		FILE *fp = fopen(down_file_name, "wb+");
		fwrite(connectx.c_str(), 1, length, fp);	//返回实际写入文本的长度,若不等于length则写文件发生错误.
		fclose(fp);
	}
	else
	{
		printf("请求的文件不存在!\n");
		curl_easy_cleanup(easy_handle);
		curl_global_cleanup();
		return -1;
	}

	// 释放资源	
	curl_easy_cleanup(easy_handle);
	curl_global_cleanup();

	return 0;
}

