#include "osec_common/osec_socket_utils.h"
#include "osec_common/socket_osec.h"
#include "common/uuid.h"
#include "common/socket_client/ISocketClientMgr.h"
#include "common/log/log.h"
#include <unistd.h>

namespace socket_control {

std::string GetProcessStringName(long process_name) {
    switch(process_name) {
        case OSEC_FRONT_UI_ID: return OSEC_FRONT_UI_NAME;
        case OSEC_FILE_NET_AGENT_ID: return OSEC_FILE_NET_AGENT_NAME;
        case OSEC_BUSINESS_NET_AGENT_ID: return OSEC_BUSINESS_NET_AGENT_NAME;
        case OSEC_BACKEND_ID: return OSEC_BACKEND_NAME;
        case OSEC_RIGHT_MENU_ID: return OSEC_RIGHT_MENU_NAME;
        case OSEC_FRONT_UI_MISC_ID: return OSEC_FRONT_UI_MISC_NAME;
    }
    return "UnKnown";
}

long GetProcessName(const std::string &str_process) {
    if (str_process == OSEC_FRONT_UI_NAME) return OSEC_FRONT_UI_ID;
    if (str_process == OSEC_FILE_NET_AGENT_NAME) return OSEC_FILE_NET_AGENT_ID;
    if (str_process == OSEC_BUSINESS_NET_AGENT_NAME) return OSEC_BUSINESS_NET_AGENT_ID;
    if (str_process == OSEC_BACKEND_NAME) return OSEC_BACKEND_ID;
    if (str_process == OSEC_RIGHT_MENU_NAME) return OSEC_RIGHT_MENU_ID;
    if (str_process == OSEC_FRONT_UI_MISC_NAME) return OSEC_FRONT_UI_MISC_ID;
    return PROCESS_UNKNOWN_ID;
}

long GetFunctionTimeOut(const std::string &str_function) {
    (void)str_function;
    long timeout = 10000;
    return timeout;
}

int SyncSendDataToOtherProcess(ISocketClientMgr *pSocketClientMgr, const std::string& str_content, const char *lpSender, const char *lpRecver, const char *lpFunction, std::string& recv_content) {
    struct UnixSocketData sendData;
    sendData.strSender = lpSender;
    sendData.strReciever = lpRecver;
    sendData.strFunction = lpFunction;
    sendData.lpContent = (unsigned char *)str_content.c_str();
    sendData.nContLen = str_content.length();
    sendData.nPriority = 0;
    char uuid[UUID_LEN];
    memset(uuid, 0, UUID_LEN);
    while (uuid::UUID_ESUCCESS != uuid::uuid4_generate(uuid)) {
        LOG_INFO("async send data from[%s] to [%s] failed, create uuid failed.", sendData.strSender.c_str(), lpRecver);
        usleep(100 * 1000);
        continue;
    }
    sendData.strUUID = uuid;
    std::string str_send;
    socket_control::CreateSendData(str_send, sendData);
    LOG_INFO("[%s] : [%s] send sync data[%s] to [%s]", sendData.strSender.c_str(), sendData.strFunction.c_str(), str_content.c_str(), lpRecver);
    IASBundle *recv_data = NULL;
    if (pSocketClientMgr) {
        pSocketClientMgr->SyncSendData(str_send.c_str(), recv_data);
    }
    if (recv_data == NULL) {
        LOG_ERROR("[%s] havn't recv the response, retry...", lpFunction);
        return -1;
    } else {
        recv_content = socket_control::getBundleBinaryInfo(recv_data, UnixSocketKeyDataContent);
        LOG_INFO("recv the [%s] response[%s].", lpFunction, recv_content.c_str());
        if (recv_data != NULL) {
            recv_data->clear();
            delete recv_data;
            recv_data = NULL;
        }
    }
    return 0;
}

void AsyncSendDataToOtherProcess(ISocketClientMgr *pSocketClientMgr, const std::string& str_content, const char *lpSender, const char *lpRecver, const char *lpFunction) {
    struct UnixSocketData sendData;
    sendData.strSender = lpSender;
    sendData.strReciever = lpRecver;
    sendData.strFunction = lpFunction;
    sendData.lpContent = (unsigned char *)str_content.c_str();
    sendData.nContLen = str_content.length();
    sendData.nPriority = 0;
    char uuid[UUID_LEN];
    memset(uuid, 0, UUID_LEN);
    while (uuid::UUID_ESUCCESS != uuid::uuid4_generate(uuid)) {
        LOG_INFO("async send data from[%s] to [%s] failed, create uuid failed.", sendData.strSender.c_str(), lpRecver);
        usleep(100 * 1000);
        continue;
    }
    sendData.strUUID = uuid;
    std::string str_send;
    socket_control::CreateSendData(str_send, sendData);
    LOG_INFO("[%s] : [%s] send async data[%s] to [%s]", sendData.strSender.c_str(), sendData.strFunction.c_str(), str_content.c_str(), lpRecver);
    if (pSocketClientMgr) {
        pSocketClientMgr->ASyncSendData(str_send.c_str());
    }
}

void ResponseCallFunc(ISocketClientMgr *pSocketClientMgr, const std::string &strResponse, const UnixSocketData &recvData) {
    struct UnixSocketData sendData;
    sendData.strSender = recvData.strReciever;
    sendData.strReciever = recvData.strSender;
    sendData.strFunction = recvData.strFunction;
    sendData.lpContent = (unsigned char *)strResponse.c_str();
    sendData.nContLen = strResponse.length();
    sendData.nPriority = recvData.nPriority;
    sendData.strUUID = recvData.strUUID;
    sendData.bResponse = true;
    std::string str_send;
    socket_control::CreateSendData(str_send, sendData);
    LOG_INFO("[%s] : [%s] response data[%s] to [%s]", sendData.strSender.c_str(), sendData.strFunction.c_str(), strResponse.c_str(), sendData.strReciever.c_str());
    if (pSocketClientMgr) {
        pSocketClientMgr->ASyncSendData(str_send.c_str());
    }
}

}
