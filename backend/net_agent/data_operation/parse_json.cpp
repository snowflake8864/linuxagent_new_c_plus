#include "backend/net_agent/data_operation/parse_json.h"
#include "common/log/log.h"
#include "common/utils/string_utils.hpp"

static std::string g_ServerIp = "";
static std::string g_ServerPort = "";

namespace parse_json {

void SetServerIp(const std::string& Ip, const std::string& port) {
    g_ServerIp = Ip;
    g_ServerPort = port;
}

int ParsePolicyInfo(const std::string &strData, const std::string &strKey, std::string &strValue) {
    bool rtn = -1;
    cJSON *root = NULL;
    do {
        root = cJSON_Parse(strData.c_str());
        if (root == NULL) {
            LOG_ERROR("parse recv policy content cJSON_Parse error.");
            break;
        }
        cJSON *data = cJSON_GetObjectItem(root, "data");
        if (data == NULL || data->type != cJSON_Array) break;

        int nSize = cJSON_GetArraySize(data);
        if (nSize == 0) break;

        cJSON *config_data = cJSON_GetArrayItem(data, 0);
        if (config_data == NULL || config_data->type != cJSON_Object) break;

        cJSON *detail = cJSON_GetObjectItem(config_data, "detail");
        if (detail == NULL || detail->type != cJSON_Object) break;

        cJSON *detail_data = cJSON_GetObjectItem(detail, strKey.c_str());
        if (detail_data == NULL || detail_data->type != cJSON_Object) break;

        char* data_info = cJSON_PrintUnformatted(detail_data);
        if (NULL == data_info) break;
        strValue = std::string(data_info);
        free(data_info);

        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}


/*

{
  "code": "000000",
  "msg": "OK",
  "data": {
    "tasklist": [
      [
        ”上传进程列表",
        "升级软件",
        "上传目录结构",
        "下载进程白名单库",
        "下载目录防御策略",
        "上传当前配置信息",
        "下载配置信息"
      ]
    ]
  }
}
 */

int ParseAllTaskInfo(const std::string &strData,TASK_BASE &vecNotifyTask) {
    if (strData.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(strData.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON* data = cJSON_GetObjectItem(root, "data");
        if (data == NULL || data->type != cJSON_Object) {
            LOG_ERROR("[ %d ] [ %s ] parse data json failed, the format error.", __LINE__, __FUNCTION__);
            return -1;
        }
        cJSON *array = cJSON_GetObjectItem(data, "tasklist");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
            int index_policy = pSub->valueint;
            vecNotifyTask.lst_type.push_back((TASK_TYPE)index_policy);
        }

        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

int ParseClientLevelFromNotifyTask(const std::string &strData, int &nLevel) {
    int rtn = -1;
    cJSON *root = cJSON_Parse(strData.c_str());
    if (root == NULL) {
        LOG_ERROR("parse json failed, the format error");
        return -1;
    }
    do {
        cJSON *data = cJSON_GetObjectItem(root, "detail");
        if (data == NULL || data->type != cJSON_Object) {
            LOG_ERROR("GetObjectItem [detail] object error");
            break;
        }
        cJSON *json_level = cJSON_GetObjectItem(data, "level");
        if (json_level == NULL || json_level->type != cJSON_Number) {
            LOG_ERROR("GetObjectItem [level] error");
            break;
        }
        nLevel = json_level->valueint;
        rtn = 0;
    } while (false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

/*
  "code": "000000",
  "msg": "OK",
  "data": {
    "conf": {
      "serveripport": "192.168.1.1:80",
      "logipport": "192.168.1.1:512",
      "logproto": "UDP",
      "logsent": "ON",
      "proc-protect": "ON",
      "file-protect": "ON",
      "comtime": "60",
      "fasttime": "2",
      "scanproctime": "300",
      "scanfiletime": "300"
    }
  }
 */
int ParaseConfJson(const std::string &str_json, CONFIG_INFO &conf) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    cJSON *data_conf = NULL;
    cJSON *data_sub = NULL;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        data_conf = cJSON_GetObjectItem(root, "data");
        if (data_conf == NULL || data_conf->type != cJSON_Object) {
            LOG_ERROR("data empty");
            break;
        }
        cJSON *data = cJSON_GetObjectItem(data_conf, "conf");
        if (data == NULL || data->type != cJSON_Object) {
            LOG_ERROR("conf empty");
            break;
        }
        data_sub = cJSON_GetObjectItem(data, "serveripport");
        if (data_sub == NULL || data_sub->type != cJSON_String) {
            LOG_ERROR("data_conf serveripport");
            break;
        }
        conf.serveripport = data_sub->valuestring;
        data_sub = cJSON_GetObjectItem(data, "logipport");
        if (data_sub == NULL || data_sub->type != cJSON_String) {
             LOG_ERROR("data_conf logipport");
            break;
        }
        conf.logipport =  data_sub->valuestring;
        data_sub = cJSON_GetObjectItem(data, "logproto");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
             LOG_ERROR("data_conf logproto");
            break;
        }

        conf.logproto = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "logsent");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf logsent");
            break;
        }
        conf.logsent = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "proc_protect");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf proc_protect");
            break;
        }
        conf.proc_protect = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "file_protect");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf file_protect");
            break;
        }
        conf.file_protect = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "crontime");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
           LOG_ERROR("data_conf crontime");
            break;
        }
        conf.crontime = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "extortion_protect");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
              LOG_ERROR("data_conf extortion_protect");
            break;
        }
        conf.extortion_protect = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "proc_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf proc_switch");
            break;
        }
        conf.proc_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "module_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf module_switch");
            break;
        }
        conf.module_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "file_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
           LOG_ERROR("data_conf file_switch");
            break;
        }
        conf.file_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "extortion_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf extortion_switch");
            break;
        }
        conf.extortion_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "usb_protect");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf usb_protect");
            break;
        }
        conf.usb_protect = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "open_port_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf open_port_switch");
            break;
        }
        conf.open_port_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "usb_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf usb_switch");
            break;
        }
        conf.usb_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "api_port");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf api_port");
            break;
        }
        conf.api_port = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "syslog_port");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
             LOG_ERROR("data_conf syslog_port");
            break;
        }
        conf.syslog_port = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "syslog_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf syslog_switch");
            break;
        }
        conf.syslog_switch = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "self_protect_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf self_protect_switch");
            break;
        }
        conf.self_protect_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "syslog_dns_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf syslog_dns_switch");
            break;
        }
        conf.syslog_dns_switch = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "syslog_outer_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf syslog_outer_switch");
            break;
        }
        conf.syslog_outer_switch = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "syslog_inner_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf syslog_inner_switch");
            break;
        }
        conf.syslog_inner_switch = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "syslog_process_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf syslog_process_switch");
            break;
        }
        conf.syslog_process_switch = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "syslog_login_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf syslog_login_switch");
            break;
        }
        conf.syslog_login_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "hardware_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf hardware_switch");
            break;
        }
        conf.hardware_switch = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "hardware_time");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            LOG_ERROR("data_conf hardware_time");
            break;
        }
        conf.hardware_time = data_sub->valueint;
        
    } while (0);
    if (root) {
        cJSON_Delete(root);
    }
    return 0;
}

int ParaseProcessWhite(const std::string &strData, std::map<std::string, std::string> &mapProcessInfo) {
    if (strData.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(strData.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *data = cJSON_GetObjectItem(root, "data");
        if (data == NULL || data->type != cJSON_Object) {
            break;
        }
        cJSON *array = cJSON_GetObjectItem(data, "proclist");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
            cJSON *dir = cJSON_GetObjectItem(pSub, "dir");
            if (dir == NULL || dir->type != cJSON_String) {
                break;
            }
            cJSON *hash = cJSON_GetObjectItem(pSub, "hash");
            if (hash == NULL || hash->type != cJSON_String) {
                break;
            }
            std::string hash_value = hash->valuestring;
            std::string process_hash = string_utils::ToLower(hash_value);
            mapProcessInfo[process_hash] = "1";
            LOG_DEBUG("ParaseProcessWhite recv hash:%s\n", process_hash.c_str());
        }
        rtn = 0;
 
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

/* 
{
    "code": "000000",
    "msg": “OK",
    “data”:{
  "code": "000000",
  "msg": "OK",
  "data": [
    {
      "dir": "/var/www/pic",
      "level": "RW",
      "type": "jpg|jpeg|gif",
      "hash": "abce5d16520de693a3fe707cdc968562",
      "child": 1
    },
    {
      "dir": "/home/web/veda",
      "level": "RW",
      "type": "php|jpeg|gif",
      "hash": "abce5d16520de693a3fe707cdc968562",
      "child": 0
    }
  ]
}
   }
*/

int ParaseProtectDir(const std::string &strData, std::vector<POLICY_PROTECT_DIR> &vecProtectDir) {
    if (strData.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(strData.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ) {
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            PROTECT_DIR dir_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "dir");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.dir = temp->valuestring;

/* 
            temp = cJSON_GetObjectItem(pSub, "notice_type");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.notice_type = temp->valueint;
*/

            temp = cJSON_GetObjectItem(pSub, "type");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.type = temp->valueint;

            temp = cJSON_GetObjectItem(pSub, "hash");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.hash = temp->valuestring;
            temp = cJSON_GetObjectItem(pSub, "protect_rw");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.protect_rw = temp->valueint;
            temp = cJSON_GetObjectItem(pSub, "protect_file");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.file_ext = temp->valuestring;
            
            temp = cJSON_GetObjectItem(pSub, "include_file");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.include_file = temp->valuestring; 

            temp = cJSON_GetObjectItem(pSub, "is_extend");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.is_extend = temp->valueint;

            temp = cJSON_GetObjectItem(pSub, "protect_folder");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            dir_mem.is_white = temp->valuestring;
            temp = cJSON_GetObjectItem(pSub, "process");
            if (temp == NULL || temp->type != cJSON_Array) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                continue;
            } else {
                int nSizeCount = cJSON_GetArraySize(temp);
                if (nSizeCount == 0) {
                    rtn = 0;
                }
                for( int jCnt = 0 ; jCnt < nSizeCount ; jCnt ++ ) {
                    cJSON * pSub_Process = cJSON_GetArrayItem(temp, jCnt);
                    if(NULL == pSub_Process ){ continue ; }

                    cJSON *temp_process = cJSON_GetObjectItem(pSub_Process, "hash");
                    if (temp_process == NULL || temp_process->type != cJSON_String) {
                        LOG_ERROR("[ %d ] [ %s ] parse temp_process json failed, the format error.", __LINE__, __FUNCTION__);
                        break;
                    }
                    std::string white_prcess = "";
                    if (jCnt != 0) {
                        white_prcess = ",";
                    }
                    white_prcess += temp_process->valuestring;
                    dir_mem.white_hash += white_prcess;
                }
            }
            vecProtectDir.push_back(dir_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

/*
{
  "code": "000000",
  "msg": "OK",
  "data": {
    "token": "eg1239dfjkj39jf29jgng204"
  }
}

 */
int ParaseOnlineJson(const std::string &strData, std::string &str_token) {
    int rtn = -1;
    cJSON *root = cJSON_Parse(strData.c_str());
    if (root == NULL) {
        LOG_ERROR("parse ParaseTokenJson failed, the format error");
        return -1;
    }
    do {
        cJSON *data = cJSON_GetObjectItem(root, "data");
        if (data == NULL || data->type != cJSON_Object) {
            LOG_ERROR("GetObjectItem data Json [detail] object error");
            break;
        }

        cJSON *token = cJSON_GetObjectItem(data, "token");
        if (token == NULL || token->type != cJSON_String) {
            LOG_ERROR("GetObjectItem ParaseToken Json [detail] object error");
            break;
        }
        str_token = token->valuestring;
        rtn = 0;
    } while (false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

int ParaseDirView(const std::string &str_json, std::vector<DIR_VIEW> &vecDirView) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *data = cJSON_GetObjectItem(root, "data");
        if (data == NULL || data->type != cJSON_Array) {
            break;
        }
        int nSize = cJSON_GetArraySize(data);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(data, iCnt);
            if(NULL == pSub ){ continue ; }
            cJSON *dir = cJSON_GetObjectItem(pSub, "dir");
            if (dir == NULL || dir->type != cJSON_String) {
                break;
            }
            
            cJSON *type = cJSON_GetObjectItem(pSub, "type");
            if (type == NULL || type->type != cJSON_Number) {
                break;
            }
            cJSON *id = cJSON_GetObjectItem(pSub, "pid");
            if (id == NULL || id->type != cJSON_Number) {
                break;
            }
            DIR_VIEW view = {dir->valuestring, type->valueint, id->valueint};
            vecDirView.push_back(view);
        }
        rtn = 0;
 
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn; 
}

int ParaseUpdateJson(const std::string &str_json, POLICY_UPDATE &update) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return -1;
    }

    cJSON *data_sub = NULL;
    int ret = -1;
    
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *data = cJSON_GetObjectItem(root, "data");
        if (data == NULL || data->type != cJSON_Object) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        data_sub = cJSON_GetObjectItem(data, "hash");
        if (data_sub == NULL || data_sub->type != cJSON_String) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        update.hash = data_sub->valuestring;
        data_sub = cJSON_GetObjectItem(data, "download");
        if (data_sub == NULL || data_sub->type != cJSON_String) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        update.downurl =  data_sub->valuestring;
        ret = 0;
    } while (0);

    if (root) {
        cJSON_Delete(root);
    }
    return ret;
  }

int ParaseSingleProcessModule(const std::string &str_json, std::vector<POLICY_SINGLE_PROCESS_SO> &vecSingleSo) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            POLICY_SINGLE_PROCESS_SO item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "hash");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.hash = temp->valuestring;


            temp = cJSON_GetObjectItem(pSub, "pid");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.pid = temp->valueint;
            vecSingleSo.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

int ParaseExiportProtect(const std::string &str_json, std::vector<POLICY_EXIPOR_PROTECT> &vecExiport) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ) {
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            POLICY_EXIPOR_PROTECT item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "type");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse type json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.type = temp->valueint;
            temp = cJSON_GetObjectItem(pSub, "file_suffix");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse file_suffix json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.file_type = temp->valuestring;
            cJSON *array_sub = cJSON_GetObjectItem(pSub, "process");
            if (array_sub == NULL || array_sub->type != cJSON_Array) {
                LOG_ERROR("[ %d ] [ %s ] parse process json array_sub failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            int nSize_sub = cJSON_GetArraySize(array_sub);
            if (nSize_sub == 0) {
                break;
            }
            for( int jCnt = 0 ; jCnt < nSize_sub ; jCnt ++ ){
                std::string name_str = "";
                std::string hash_str = "";
                cJSON * array_sub_item = cJSON_GetArrayItem(array_sub, jCnt);
                if(NULL == array_sub_item ){ continue ; }
        
                cJSON* temp_sub = cJSON_GetObjectItem(array_sub_item, "hash");
                if (temp_sub == NULL || temp_sub->type != cJSON_String) {
                    LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                    break;
                }
                hash_str = temp_sub->valuestring;

                temp_sub = cJSON_GetObjectItem(array_sub_item, "name");
                if (temp_sub == NULL || temp_sub->type != cJSON_String) {
                    LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                    break;
                }
                name_str = temp_sub->valuestring;
                item_mem.map_comm[name_str] = hash_str;
            }
            vecExiport.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}


int ParasePolicyProcessModule(const std::string &str_json, std::vector<POLICY_PROCESS_MODULE_SO> &vecExiport) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            POLICY_PROCESS_MODULE_SO item_mem;
            // cJSON *temp = cJSON_GetObjectItem(pSub, "moduleId");
            // if (temp == NULL || temp->type != cJSON_Number) {
            //     LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            //     break;
            // }
            // item_mem.moduleId = temp->valueint;

            // temp = cJSON_GetObjectItem(pSub, "dir");
            // if (temp == NULL || temp->type != cJSON_String) {
            //     LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            //     break;
            // }
            // item_mem.dir = temp->valuestring;
            cJSON *temp = NULL;
            temp = cJSON_GetObjectItem(pSub, "hash");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.hash = temp->valuestring;
            vecExiport.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;

}

int ParasePolicyVirtual(const std::string &str_json, std::vector<PORT_REDIRECT> &lstPort_policy) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            PORT_REDIRECT item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "id");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.id = temp->valueint;

            temp = cJSON_GetObjectItem(pSub, "type");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.type = temp->valuestring;

            temp = cJSON_GetObjectItem(pSub, "alarm_level");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.alarm_level = temp->valueint;

            temp = cJSON_GetObjectItem(pSub, "source_ip");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.source_ip = temp->valuestring;

            temp = cJSON_GetObjectItem(pSub, "source_port");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.source_port = temp->valuestring;

            temp = cJSON_GetObjectItem(pSub, "dest_ip");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.dest_ip = temp->valuestring;


            temp = cJSON_GetObjectItem(pSub, "dest_port");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.dest_port = temp->valuestring;

            temp = cJSON_GetObjectItem(pSub, "protocol");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.protocol = temp->valuestring;
            lstPort_policy.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

int ParaseNetWhiteBlack(const std::string &str_json, std::vector<NET_PROTECT_IP> &lstPolicy, const int type) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            NET_PROTECT_IP item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "ip");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.ip = temp->valuestring;
            if (g_ServerIp.find(item_mem.ip) !=  std::string::npos) {
                LOG_ERROR("[ %d ] [ %s ] parse json g_ServerIp is include .", __LINE__, __FUNCTION__);
                continue;
            }

            temp = cJSON_GetObjectItem(pSub, "direction");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }

            item_mem.direction = temp->valueint;
            item_mem.type = type;
            lstPolicy.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

int ParaseNetBlockList(const std::string &str_json, std::vector<NETBLOCK> &lstPolicy) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            NETBLOCK item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "ip");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.ip = temp->valuestring;
            if (g_ServerIp.find(item_mem.ip) !=  std::string::npos) {
                LOG_ERROR("[ %d ] [ %s ] parse json g_ServerIp is include .", __LINE__, __FUNCTION__);
                continue;
            }
            temp = cJSON_GetObjectItem(pSub, "type");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.type = temp->valuestring;
            temp = cJSON_GetObjectItem(pSub, "typeName");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.endtime = temp->valuestring;
            temp = cJSON_GetObjectItem(pSub, "direction");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.direction = temp->valueint;
            lstPolicy.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

int ParaseUSBInfoPolicy(const std::string &str_json, std::vector<USB_INFO> &lstPolicy, const int nAllow) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            USB_INFO item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "perpheral_eid");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.eid= temp->valuestring;
            temp = cJSON_GetObjectItem(pSub, "perpheral_name");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.name = temp->valuestring;
            item_mem.nAllow = nAllow;
            lstPolicy.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;
}

int ParaseSampleInfo(const std::string &str_json, std::vector<SAMPLE_INFO> &lstSample) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            SAMPLE_INFO item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "aid");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.aid = temp->valueint;
            temp = cJSON_GetObjectItem(pSub, "p_dir");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.p_dir = temp->valuestring;
            temp = cJSON_GetObjectItem(pSub, "p_hash");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.p_hash = temp->valuestring;
            lstSample.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;   
}

int ParaseSysLogConfJson(const std::string &str_json, SYSLOG_INFO &conf) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    cJSON *data_conf = NULL;
    cJSON *data_sub = NULL;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        data_conf = cJSON_GetObjectItem(root, "data");
        if (data_conf == NULL || data_conf->type != cJSON_Object) {
            break;
        }
        cJSON *data = cJSON_GetObjectItem(data_conf, "conf");
        if (data == NULL || data->type != cJSON_Object) {
            break;
        }
        data_sub = cJSON_GetObjectItem(data, "api_port");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            break;
        }
        conf.api_port = data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "syslog_port");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            break;
        }
        conf.syslog_port =  data_sub->valueint;
        data_sub = cJSON_GetObjectItem(data, "proc_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            break;
        }
        conf.proc_switch = data_sub->valueint;

        data_sub = cJSON_GetObjectItem(data, "syslog_process_switch");
        if (data_sub == NULL || data_sub->type != cJSON_Number) {
            break;
        }
        conf.syslog_process_switch = data_sub->valueint;

    } while (0);
    if (root) {
        cJSON_Delete(root);
    }
    return 0;
}

int ParaseGettrustdirJson(const std::string &str_json, std::vector<GlobalTrusrDir> &lsttrustdir) {
    if (str_json.empty()) {
        LOG_INFO("[ %d ] [ %s ] strData is empty.", __LINE__, __FUNCTION__);
        return 0;
    }

    int rtn = -1;
    cJSON *root = cJSON_Parse(str_json.c_str());
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
        return -1;
    }
    do {
        cJSON *array = cJSON_GetObjectItem(root, "data");
        if (array == NULL || array->type != cJSON_Array) {
            LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
            break;
        }
        int nSize = cJSON_GetArraySize(array);
        if (nSize == 0) {
            rtn = 0;
            break;
        }

        for( int iCnt = 0 ; iCnt < nSize ; iCnt ++ ){
            cJSON * pSub = cJSON_GetArrayItem(array, iCnt);
            if(NULL == pSub ){ continue ; }
        
            GlobalTrusrDir item_mem;
            cJSON *temp = cJSON_GetObjectItem(pSub, "type");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.type = temp->valueint;
            temp = cJSON_GetObjectItem(pSub, "dir");
            if (temp == NULL || temp->type != cJSON_String) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.dir = temp->valuestring;
            temp = cJSON_GetObjectItem(pSub, "is_extend");
            if (temp == NULL || temp->type != cJSON_Number) {
                LOG_ERROR("[ %d ] [ %s ] parse json failed, the format error.", __LINE__, __FUNCTION__);
                break;
            }
            item_mem.is_extend = temp->valueint;
            lsttrustdir.push_back(item_mem);
        }
        rtn = 0;
    } while(false);
    if (root) {
        cJSON_Delete(root);
    }
    return rtn;   
}

}

