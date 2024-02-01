#include "common/socket/socket_utils.h"
#include "common/ASFramework/ASBundle.h"
#include "common/ASFramework/ASBundleImpl.hpp"
#include "common/ASFramework/util/ASBase64.h"
#include "common/log/log.h"

namespace socket_control {
    int GetJsonItemInfo(cJSON *object, const char *key, std::string &value, int type) {
        cJSON* item = cJSON_GetObjectItem(object, key);
        if (item == NULL || item->type != type) {
            LOG_ERROR("convert recv json data, parse %s info failed.", key);
            return -1;
        }
        value = item->valuestring;
        return 0;
    }
    int GetJsonItemInfo(cJSON *object, const char *key, unsigned int &value, int type) {
        cJSON* item = cJSON_GetObjectItem(object, key);
        if (item == NULL || item->type != type) {
            LOG_ERROR("convert recv json data, parse %s info failed.", key);
            return -1;
        }
        value = item->valueint;
        return 0;
    }
    int GetJsonItemInfo(cJSON *object, const char *key, bool &value, int type) {
        cJSON* item = cJSON_GetObjectItem(object, key);
        if (item == NULL || (item->type != cJSON_True && item->type != cJSON_False)) {
            LOG_ERROR("convert recv json data, parse %s info failed.", key);
            return -1;
        }
        value = (item->type == cJSON_True ? true : false);
        return 0;
    }
    int ConvertRecvStrToBundle(IASBundle** pSocketData, const std::string& recv_data) {
        int rtn = -1;
        if (recv_data.empty()) {
            LOG_ERROR("convert recv data to bundle, parse sender info failed, recv_data is empty.");
            return rtn;
        }
        // 解析json串
        cJSON* json = cJSON_Parse(recv_data.c_str());
        if (json == NULL) {
            LOG_ERROR("convert recv data to bundle, parse sender info failed, json format error.");
            return rtn;
        }
        // 拼凑Bundle
        (*pSocketData) = CASBundle::CreateInstance();
        if (!(*pSocketData)) {
            LOG_ERROR("convert recv data to bundle, create bundle failed.");
            return rtn;
        }
        struct UnixSocketData recvData;
        do {
            if (GetJsonItemInfo(json, UnixSocketKeyDataSender, recvData.strSender, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataRecver, recvData.strReciever, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataPriority, recvData.nPriority, cJSON_Number) != 0) break;
            std::string str_content;
            if (GetJsonItemInfo(json, UnixSocketKeyDataContent, str_content, cJSON_String) != 0) break;
            if (str_content.length()) {
                recvData.lpContent = ASBase64Util::Base64Decode(str_content, recvData.nContLen);
                LOG_DEBUG("convert recv str to bundle, str[%s], len[%d]", std::string((char *)recvData.lpContent, recvData.nContLen).c_str(), recvData.nContLen);
            } else {
                LOG_ERROR("convert recv data to bundle, recv data's content is NULL.");
                break;
            }
            if (GetJsonItemInfo(json, UnixSocketKeyDataUniqueID, recvData.strUUID, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataFunction, recvData.strFunction, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataResponed, recvData.bResponse, cJSON_True) != 0) break;
            rtn = 0;
        } while(false);
        if (NULL != json) {
            cJSON_Delete(json);
        }
        if (rtn == -1) {
            LOG_ERROR("convert recv data to bundle, parse json error.");
        } else {
            (*pSocketData)->putBinary(UnixSocketKeyDataContent, recvData.lpContent, recvData.nContLen);
            (*pSocketData)->putInt(UnixSocketKeyDataContLen, recvData.nContLen);
            (*pSocketData)->putAString(UnixSocketKeyDataSender, (char *)recvData.strSender.c_str());
            (*pSocketData)->putAString(UnixSocketKeyDataRecver, (char *)recvData.strReciever.c_str());
            (*pSocketData)->putInt(UnixSocketKeyDataPriority, recvData.nPriority);
            (*pSocketData)->putAString(UnixSocketKeyDataUniqueID, (char *)recvData.strUUID.c_str());
            (*pSocketData)->putAString(UnixSocketKeyDataFunction, (char *)recvData.strFunction.c_str());
            (*pSocketData)->putInt(UnixSocketKeyDataResponed, recvData.bResponse ? 1 : 0);
        }
        recvData.clear();
        return rtn;
    }
    int GetBundleItemInfo(IASBundle* pBundle, const char *key, unsigned char * &value) {
        int nInBufLen = 0;
        if((ASErr_INSUFFICIENT_BUFFER != pBundle->getBinary(key,NULL,&nInBufLen)) || nInBufLen <= 0) {
            LOG_ERROR("get bundle info[%s] failed, because get binary length failed.", key);
            return -1;
        } else {
            value = new (std::nothrow) unsigned char[nInBufLen];
            if (!value) {
                LOG_ERROR("get bundle info[%s] failed, because out of memory.", key);
                return -1;
            }
            memset(value, 0, nInBufLen);
            if((0 != pBundle->getBinary(key, value, &nInBufLen)) || nInBufLen <= 0) {
                LOG_ERROR("get bundle info[%s] failed, because get binary buffer failed.", key);
                return -1;
            }
        }
        return 0;
    }
    int GetBundleItemInfo(IASBundle* pBundle, const char *key, std::string &value) {
        int nInBufLen = 0;
        if((ASErr_INSUFFICIENT_BUFFER != pBundle->getAString(key,NULL,&nInBufLen)) || nInBufLen <= 0) {
            LOG_ERROR("get bundle info[%s] failed, because get string length failed.", key);
            return -1;
        } else {
            char *lpValue = new (std::nothrow) char[nInBufLen];
            if (!lpValue) {
                LOG_ERROR("get bundle info[%s] failed, because out of memory.", key);
                return -1;
            }
            memset(lpValue, 0, nInBufLen);
            if((0 != pBundle->getAString(key, lpValue, &nInBufLen)) || nInBufLen <= 0) {
                LOG_ERROR("get bundle info[%s] failed, because get string buffer failed.", key);
                if (NULL != lpValue) delete [] lpValue;
                return -1;
            }
            value = std::string(lpValue);
            if (NULL != lpValue) delete [] lpValue;
        }
        return 0;
    }
    int GetBundleItemInfo(IASBundle* pBundle, const char *key, unsigned int &value) {
        pBundle->getInt(key, (int *)&value);
        return 0;
    }
    int GetBundleItemInfo(IASBundle* pBundle, const char *key, bool &value) {
        int nValue;
        pBundle->getInt(key, &nValue);
        value = (nValue == 1 ? true : false);
        return 0;
    }
    int ParseRecvBundleData(IASBundle* pSocketData, struct UnixSocketData &recvData) {
        if (!pSocketData) {
            LOG_ERROR("parse recv bundle data failed, bundle is null.");
            return -1;
        }
        int rtn = -1;
        do {
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataContent, recvData.lpContent) != 0) break;
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataContLen, recvData.nContLen) != 0) break;
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataSender, recvData.strSender) != 0) break;
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataRecver, recvData.strReciever) != 0) break;
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataPriority, recvData.nPriority) != 0) break;
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataUniqueID, recvData.strUUID) != 0) break;
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataFunction, recvData.strFunction) != 0) break;
            if (GetBundleItemInfo(pSocketData, UnixSocketKeyDataResponed, recvData.bResponse) != 0) break;
            rtn = 0;
        } while(false);
        return rtn;
    }
    int CreateSendData(std::string& send_data, const struct UnixSocketData &recvData) {
        int rtn = -1;
        do {
            std::string str_base64 = ASBase64Util::Base64Encode(recvData.lpContent, recvData.nContLen);
            cJSON * json = cJSON_CreateObject();
            if (NULL == json) {
                LOG_ERROR("create json object failed, because out of memory.");
                break;
            }
            cJSON_AddStringToObject(json, UnixSocketKeyDataContent, str_base64.c_str());
            cJSON_AddStringToObject(json, UnixSocketKeyDataSender, recvData.strSender.c_str());
            cJSON_AddStringToObject(json, UnixSocketKeyDataRecver, recvData.strReciever.c_str());
            cJSON_AddNumberToObject(json, UnixSocketKeyDataPriority, recvData.nPriority);
            cJSON_AddStringToObject(json, UnixSocketKeyDataUniqueID, recvData.strUUID.c_str());
            cJSON_AddStringToObject(json, UnixSocketKeyDataFunction, recvData.strFunction.c_str());
            cJSON_AddBoolToObject(json, UnixSocketKeyDataResponed, recvData.bResponse);
            char * json_str = cJSON_PrintUnformatted(json);
            if (NULL != json_str) {
                send_data = std::string(json_str);
                free(json_str);
            } else {
                LOG_ERROR("format json into send data string failed.");
                break;
            }
            if (NULL != json) {
                cJSON_Delete(json);
            }
            rtn = 0;
        } while (false);
        return rtn;
    }
    int CreateSendData(std::string& send_data, IASBundle *pSocketData) {
        struct UnixSocketData sendData;
        if (-1 == ParseRecvBundleData(pSocketData, sendData)) {
            LOG_ERROR("create send data from bundle failed, parse bunlde info failed.");
            return -1;
        }
        if (-1 == CreateSendData(send_data, sendData)) {
            LOG_ERROR("create send data from bundle failed, create send data failed.");
            return -1;
        }
        sendData.clear();
        return 0;
    }
    int ParseSendJsonData(const std::string& send_data, struct UnixSocketData& sendData) {
        int rtn = -1;
        if (send_data.empty()) {
            LOG_ERROR("parse send json data info failed, input string is null.");
            return rtn;
        }
        cJSON* json = NULL;
        do {
            json = cJSON_Parse(send_data.c_str());
            if (json == NULL) {
                LOG_ERROR("parse send json data info failed, format error.");
                break;
            }
            if (GetJsonItemInfo(json, UnixSocketKeyDataSender, sendData.strSender, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataRecver, sendData.strReciever, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataPriority, sendData.nPriority, cJSON_Number) != 0) break;
            std::string str_content;
            if (GetJsonItemInfo(json, UnixSocketKeyDataContent, str_content, cJSON_String) != 0) break;
            if (str_content.length()) {
                sendData.lpContent = ASBase64Util::Base64Decode(str_content, sendData.nContLen);
                LOG_DEBUG("convert recv str to bundle, str[%s], len[%d]", std::string((char *)sendData.lpContent, sendData.nContLen).c_str(), sendData.nContLen);
            } else {
                LOG_ERROR("convert recv data to bundle, recv data's content is NULL.");
                break;
            }
            if (GetJsonItemInfo(json, UnixSocketKeyDataUniqueID, sendData.strUUID, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataFunction, sendData.strFunction, cJSON_String) != 0) break;
            if (GetJsonItemInfo(json, UnixSocketKeyDataResponed, sendData.bResponse, cJSON_True) != 0) break;
            rtn = 0;
        } while(false);
        if (json) cJSON_Delete(json);
        return rtn;
    }
    std::string getBundleBinaryInfo(IASBundle *pData, const char *str_key) {
        int rtn = 0;
        unsigned char *lpValue = NULL;
        int nInBufLen = 0;
        do {
            if((ASErr_INSUFFICIENT_BUFFER != (rtn = pData->getBinary(str_key,NULL,&nInBufLen))) || nInBufLen <= 0) {
                break;
            } else {
                lpValue = new (std::nothrow) unsigned char[nInBufLen];
                if (!(lpValue)) {
                    rtn = -1;
                    break;
                }
                memset(lpValue, 0, nInBufLen);
                if(0 != (rtn = pData->getBinary(str_key, lpValue, &nInBufLen)) || nInBufLen <= 0)
                    break;
            }
        } while(false);
        if (rtn == -1) {
            LOG_ERROR("parse recv bundle error, get str_key[%s] failed.", str_key);
            return "";
        }
        std::string result = std::string((char *)lpValue, nInBufLen);
        if (lpValue) delete [] lpValue;
        return result;
    }
    std::string GetBundleStringInfo(IASBundle* pData, const char* str_key) {
        int rtn = 0;
        char *lpValue = NULL;
        int nInBufLen = 0;
        do {
            if((ASErr_INSUFFICIENT_BUFFER != (rtn = pData->getAString(str_key,NULL,&nInBufLen))) || nInBufLen <= 0) {
                break;
            } else {
                lpValue = new (std::nothrow) char[nInBufLen];
                if (!(lpValue)) {
                    rtn = -1;
                    break;
                }
                memset(lpValue, 0, nInBufLen);
                if(0 != (rtn = pData->getAString(str_key, lpValue, &nInBufLen)) || nInBufLen <= 0)
                    break;
            }
        } while(false);
        if (rtn == -1) {
            LOG_ERROR("parse recv bundle error, get str_key[%s] failed.", str_key);
            return "";
        }
        std::string result = std::string(lpValue, nInBufLen - 1);
        if (lpValue) delete [] lpValue;
        return result;
    }
    std::string GetJsonStringInfo(const std::string& json_data, const char * str_key) {
        std::string str_value("");
        cJSON* json = NULL;
        json = cJSON_Parse(json_data.c_str());
        if (json == NULL) return str_value;
        cJSON* item = cJSON_GetObjectItem(json, str_key);
        if (item) {
            str_value = item->valuestring;
        } else {
            LOG_ERROR("parse send data error, get str_key[%s] failed.", str_key);
        }
        if (json) cJSON_Delete(json);
        return str_value;
    }
}
