#include "common/json/cJSON.h"
#include "common/log/log.h"
#include "common/utils/string_utils.hpp"
#include "common/pcinfo/pc_base_info.h"
#include "common/pcinfo/system_info.h"
#include "common/utils/time_utils.hpp"
#include "build_json.h"
#include "common/md5sum.h"

namespace build_json {

int BuildAuthOnlineJson(const BASE_ONLINE &base_online, std::string &strData) {
    cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddStringToObject(root, "uid", base_online.uid.c_str());
    cJSON_AddStringToObject(root, "macid", base_online.macid.c_str());
    cJSON_AddStringToObject(root, "ip", base_online.ip.c_str());
    cJSON_AddStringToObject(root, "ver", base_online.ver.c_str());
    cJSON_AddNumberToObject(root, "type", base_online.type);
    cJSON_AddStringToObject(root, "os", base_online.os.c_str());
    cJSON_AddStringToObject(root, "memsize", base_online.memsize.c_str());
    cJSON_AddStringToObject(root, "cpu", base_online.cpu.c_str());
    cJSON_AddStringToObject(root, "hdsize", base_online.hdsize.c_str());
    cJSON_AddStringToObject(root, "asstarttime", base_online.astarttime.c_str());
    cJSON_AddStringToObject(root, "osstarttime", base_online.osstarttime.c_str());
    cJSON_AddStringToObject(root, "auth", base_online.auth.c_str());
    cJSON_AddStringToObject(root, "userid", base_online.userid.c_str());
    cJSON_AddStringToObject(root, "host_name", base_online.host_name.c_str());
    
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        strData = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

/*

{
    "uid": "3a3fe707cdc96204",
    "auth": "E4805d16520de693a3fe707cdc962045"
}

 */
int BuildRequestJson(const std::string &str_uid, const std::string &auth, std::string str_json) {
    cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddStringToObject(root, "uid", str_uid.c_str());
    cJSON_AddStringToObject(root, "auth", auth.c_str());
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

/* {
        "proclist":”[
        {
            "id": 1002,
            "user": "user1",
            "dir": "/usr/libexec/ibus-x11 —kill-daemon",
            "hash": "0ca175b9c0f726a831d895e269332461"
        },
        {
            "id": 1003,
            "user": "admin",
            "dir": "/usr/libexec/ibus-x11 —kill-daemon",
            "hash": "0ca175b9c0f726a831d895e269332461"
        }
      ]
   }
 */

int BuildProcessListJson(std::vector<Audit_PROCESS> &processinfo, std::string &str_json, const int &nfinish) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    if ((nfinish ==0) || (nfinish ==100)) {
        cJSON_AddItemToObject(root,"finish", cJSON_CreateNumber(nfinish));
    }
    cJSON_AddItemToObject(root, "proclist", array_data);
    
    std::vector<Audit_PROCESS>::iterator iter;
    for (iter = processinfo.begin(); iter != processinfo.end(); iter++) {
    
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"id", cJSON_CreateNumber(iter->nProcessID));
        cJSON_AddItemToObject(mem,"user", cJSON_CreateString(iter->strUser.c_str()));
        cJSON_AddItemToObject(mem,"dir", cJSON_CreateString(iter->strExecutablePath.c_str()));
        if (iter->hash.empty()) {
            std::string md5 =  md5sum::md5file(iter->strExecutablePath.c_str());
            cJSON_AddItemToObject(mem,"hash", cJSON_CreateString(md5.c_str()));
        } else {
             cJSON_AddItemToObject(mem,"hash", cJSON_CreateString(iter->hash.c_str()));
        }


        int number_count = 0;
        number_count = iter->map_depends.size();
        cJSON_AddItemToObject(mem,"module_number", cJSON_CreateNumber(number_count));

        if ((iter->map_depends.size() > 0)) {
            cJSON *array_module = cJSON_CreateArray();
            if (array_module == NULL) {
                LOG_ERROR("[ %d ] [ %s ] array_module or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
                break;
            }
            cJSON_AddItemToObject(mem, "module", array_module);
            std::vector<std::string>::iterator iter_module;
            for (iter_module = iter->map_depends.begin(); iter_module != iter->map_depends.end(); iter_module++) {
                std::string module_hash = md5sum::md5file(iter_module->c_str());
                cJSON *mem_module = cJSON_CreateObject();
                if (mem_module == NULL) {
                    LOG_ERROR("[ %d ] [ %s ] mem_module or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
                    break;
                }
                std::string module_name = iter_module->c_str();
                 if ( (module_hash.empty()) || (module_name.empty()) ) {
                     continue;
                 }
                cJSON_AddItemToObject(mem_module,"name", cJSON_CreateString(module_name.c_str()));
                cJSON_AddItemToObject(mem_module,"hash", cJSON_CreateString(module_hash.c_str()));
                cJSON_AddItemToObject(mem_module,"attribute", cJSON_CreateString("GNU/Linux"));
                cJSON_AddItemToArray(array_module, mem_module);
            }
        }
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildAutoProcessListJson(std::vector<Audit_PROCESS> &processinfo, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "proclist", array_data);
    
    std::vector<Audit_PROCESS>::iterator iter;
    for (iter = processinfo.begin(); iter != processinfo.end(); iter++) {
    
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"id", cJSON_CreateNumber(iter->nProcessID));
        cJSON_AddItemToObject(mem,"user", cJSON_CreateString(iter->strUser.c_str()));
        cJSON_AddItemToObject(mem,"dir", cJSON_CreateString(iter->strExecutablePath.c_str()));
        if (iter->hash.empty()) {
            std::string md5 =  md5sum::md5file(iter->strExecutablePath.c_str());
            cJSON_AddItemToObject(mem,"hash", cJSON_CreateString(md5.c_str()));
        } else {
             cJSON_AddItemToObject(mem,"hash", cJSON_CreateString(iter->hash.c_str()));
        }
        cJSON_AddItemToObject(mem,"copyright", cJSON_CreateString("linux gun"));
        cJSON_AddItemToObject(mem,"introduce", cJSON_CreateString("linux"));

        // cJSON *mem_sig = cJSON_CreateObject();
        // if (mem_sig) {
        //      cJSON *mem_sig = cJSON_CreateObject();
        //     cJSON_AddItemToObject(mem_sig,"name", cJSON_CreateString("veda"));
        //     cJSON_AddItemToObject(mem_sig,"status", cJSON_CreateNumber(1));
        // }
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildSelfProtectJson(struct Audit_SelfProtect &info, std::string &str_json) 
{
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "alert", array_data);
    cJSON *mem = cJSON_CreateObject();
    cJSON_AddItemToObject(mem,"level", cJSON_CreateNumber(info.nLevel));
    cJSON_AddItemToObject(mem,"time", cJSON_CreateNumber(info.nTime));
    cJSON_AddItemToObject(mem,"type", cJSON_CreateNumber(info.nType));
    cJSON_AddItemToObject(mem,"proc_dir", cJSON_CreateString(info.procDir.c_str()));
    cJSON_AddItemToObject(mem,"proc_hash", cJSON_CreateString(info.hash.c_str()));
    if (info.param.empty()) {
        cJSON_AddItemToObject(mem, "proc_param", cJSON_CreateString(info.procDir.c_str()));
    } else {
        cJSON_AddItemToObject(mem, "proc_param", cJSON_CreateString(info.param.c_str()));
    }
    cJSON_AddItemToObject(mem, "file_dir", cJSON_CreateString(info.fileDir.c_str()));
    if (!info.targetDir.empty())
        cJSON_AddItemToObject(mem, "target_dir", cJSON_CreateString(info.targetDir.c_str()));

    cJSON_AddItemToArray(array_data, mem);
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

/*
   "conf"：{
      "serveripport": "192.168.1.1:80",
      "logipport": "192.168.1.1:512",
      "logproto": "UDP",
      "logsent": "ON",
      "proc-protect": "ON",
      "file-protect": "ON",
      "crontime": "60"
    }
 */
int BuildConfJson(CONFIG_INFO conf, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }

    cJSON_AddItemToObject(root, "conf", array_data);
    
    cJSON_AddStringToObject(array_data, "serveripport", conf.serveripport.c_str());
    cJSON_AddStringToObject(array_data, "logipport", conf.logipport.c_str());
    cJSON_AddNumberToObject(array_data, "logproto", conf.logproto);
    cJSON_AddNumberToObject(array_data, "logsent", conf.logsent);
    cJSON_AddNumberToObject(array_data, "proc-protect", conf.proc_protect);
    cJSON_AddNumberToObject(array_data, "file-protect", conf.file_protect);
    cJSON_AddNumberToObject(array_data, "crontime", conf.crontime);
    cJSON_AddNumberToObject(array_data, "extortion_protect", conf.extortion_protect);
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}
/* 
   “dir” : “[
    {
      "dir": "/var/www",
      "rw": "drwxr-xr-x",
      "group": "jeno",
      "user": "staff",
      "size": 224,
      "starttime": "123123123123",
      "updatetime": "123123123123",
      "level": "RWX",
      "type": "php|jpeg|gif",
      "hash": "edae5d16520de6edasef707cdc968543"
    },
    {
      "dir": "/var/www",
      "rw": "drwxr-xr-x",
      "group": "jeno",
      "user": "staff",
      "size": 224,
      "starttime": "123123123123",
      "updatetime": "123123123123",
      "level": "RWX",
      "type": "php|jpeg|gif",
      "hash": "edae5d16520de6edasef707cdc968543"
    }
    */
int BuildDirInfoJson(std::vector<FILE_INFO>& dirinfo, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "dir", array_data);
    
    std::vector<FILE_INFO>::iterator iter;
    for (iter = dirinfo.begin(); iter != dirinfo.end(); iter++) {
    
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"dir", cJSON_CreateString(iter->dir.c_str()));
        cJSON_AddItemToObject(mem,"rw", cJSON_CreateString(iter->rw.c_str()));
        cJSON_AddItemToObject(mem,"group", cJSON_CreateString(iter->group.c_str()));
        cJSON_AddItemToObject(mem,"user", cJSON_CreateString(iter->user.c_str()));
        cJSON_AddItemToObject(mem,"size", cJSON_CreateString(iter->size.c_str()));
        cJSON_AddItemToObject(mem,"updatetime", cJSON_CreateString(iter->starttime.c_str()));
        cJSON_AddItemToObject(mem,"starttime", cJSON_CreateString(iter->updatetime.c_str()));

        // cJSON_AddItemToObject(mem,"starttime", cJSON_CreateString(iter->starttime.c_str()));
        // cJSON_AddItemToObject(mem,"updatetime", cJSON_CreateString(iter->updatetime.c_str()));
        //cJSON_AddItemToObject(mem,"level", cJSON_CreateString(iter->level.c_str()));
        cJSON_AddItemToObject(mem,"dirtype", cJSON_CreateString(iter->dirtype.c_str()));
        cJSON_AddItemToObject(mem,"hash", cJSON_CreateString(iter->hash.c_str()));
        cJSON_AddItemToObject(mem,"type", cJSON_CreateNumber(iter->type));  //1 : dir , 2:file
        cJSON_AddItemToObject(mem,"pid", cJSON_CreateNumber(iter->id));
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}


/*
  “alert” : “alert default { 
[
	‘level’=>0 // 告警级别
	‘time’=>时间戳 //告警时间
	‘type’=>0 //告警类型  ——
	‘file’=> /var/www/index.php //文件路径
	‘hash’=> abce5d16520de693a3fe707cdc968562 //文件hash 
]
				
}”

}
struct LOG_INFO {
    std::string file_path;
    std::string md5;
    int nType;
    int nLevel;
    long nTime;
};
 */
int BuildAlertLogJson(std::vector<LOG_INFO>& loginfo, std::string &str_json) {

   cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "alert", array_data);
    
    std::vector<LOG_INFO>::iterator iter;
    for (iter = loginfo.begin(); iter != loginfo.end(); iter++) {
    
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"level", cJSON_CreateNumber(iter->nLevel));
        cJSON_AddItemToObject(mem,"time", cJSON_CreateNumber(iter->nTime));
        cJSON_AddItemToObject(mem,"type", cJSON_CreateNumber(iter->nType));
        cJSON_AddItemToObject(mem,"dir", cJSON_CreateString(iter->file_path.c_str()));
        cJSON_AddItemToObject(mem,"hash", cJSON_CreateString(iter->md5.c_str()));
        if (!(iter->rename_dir.empty())) {
            cJSON_AddItemToObject(mem,"rename_dir", cJSON_CreateString(iter->rename_dir.c_str()));
        }
        if (!(iter->notice_remark.empty())) {
            cJSON_AddItemToObject(mem,"notice_remark", cJSON_CreateString(iter->notice_remark.c_str()));
        }
        if (!(iter->exception_process.empty())) {
            cJSON_AddItemToObject(mem,"exception_process", cJSON_CreateString(iter->exception_process.c_str()));
        }

        if (!(iter->peripheral_name.empty())) {
            cJSON_AddItemToObject(mem,"peripheral_name", cJSON_CreateString(iter->peripheral_name.c_str()));
        }
        if (!(iter->peripheral_remark.empty())) {
            cJSON_AddItemToObject(mem,"peripheral_remark", cJSON_CreateString(iter->peripheral_remark.c_str()));
        }
        if (!(iter->peripheral_eid.empty())) {
            cJSON_AddItemToObject(mem,"peripheral_eid", cJSON_CreateString(iter->peripheral_eid.c_str()));
        }
        if (!(iter->p_param.empty())) {
            cJSON_AddItemToObject(mem,"p_param", cJSON_CreateString(iter->p_param.c_str()));
        } else {
            cJSON_AddItemToObject(mem,"p_param", cJSON_CreateString(iter->file_path.c_str()));
        }

        cJSON_AddItemToArray(array_data, mem);
    }
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int write_json_file(const std::string& str_file, const std::string& str_json) {
    FILE *f = NULL;
    f = fopen(str_file.c_str(), "wb");
    if(f == NULL)
    {
        fprintf(stderr, "error opening input file %s\n", str_file.c_str());
        goto err;
    }
    if(fwrite(str_json.c_str(), (size_t)str_json.length(), 1, f) != 1)
    {
        fprintf(stderr, "fwrite() failed\n");
        goto err;
    }
err:
    fclose(f);
    return 0;
}

int read_json_file(const std::string& str_file, std::string& str_json) {
    FILE *f = NULL;
    char *buf = NULL;
    long siz_buf;

    f = fopen(str_file.c_str(), "rb");
    if(f == NULL)
    {
        fprintf(stderr, "error opening input file %s\n", str_file.c_str());
        goto err;
    }

    fseek(f, 0, SEEK_END);

    siz_buf = ftell(f);
    rewind(f);

    if(siz_buf < 1) goto err;

    buf = (char*)malloc((size_t)siz_buf);
    if(buf == NULL)
    {
        fprintf(stderr, "malloc() failed\n");
        goto err;
    }

    if(fread(buf, (size_t)siz_buf, 1, f) != 1)
    {
        fprintf(stderr, "fread() failed\n");
        goto err;
    }
    str_json = buf;
err:
    free(buf);
    fclose(f);
    return 0;
}


int BuildBusinessPortJson(std::vector<PORT_BUSINESS_LIST>& loginfo, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "service", array_data);
    
    std::vector<PORT_BUSINESS_LIST>::iterator iter;
    for (iter = loginfo.begin(); iter != loginfo.end(); iter++) {
        
        std::string local_port = string_utils::ToString(iter->nLocalPort);
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"type", cJSON_CreateString(iter->strProtocol.c_str()));
        cJSON_AddItemToObject(mem,"ip", cJSON_CreateString(iter->strLocalIP.c_str()));
        cJSON_AddItemToObject(mem,"port", cJSON_CreateString(local_port.c_str()));
        cJSON_AddItemToObject(mem,"process", cJSON_CreateString(iter->strProcessPath.c_str()));
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildBusinessPortJson_ex(std::map<std::string, PORT_BUSINESS_LIST>& loginfo, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "service", array_data);
    
    std::map<std::string, PORT_BUSINESS_LIST>::iterator iter;
    for (iter = loginfo.begin(); iter != loginfo.end(); iter++) {
        
        std::string local_port = string_utils::ToString(iter->second.nLocalPort);
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"type", cJSON_CreateString(iter->second.strProtocol.c_str()));
        cJSON_AddItemToObject(mem,"ip", cJSON_CreateString(iter->second.strLocalIP.c_str()));
        cJSON_AddItemToObject(mem,"port", cJSON_CreateString(local_port.c_str()));
        cJSON_AddItemToObject(mem,"process", cJSON_CreateString(iter->second.strProcessPath.c_str()));
        cJSON_AddItemToArray(array_data, mem);
        LOG_INFO("port[%s],prot[%s], process[%s]\n", local_port.c_str(), iter->second.strProtocol.c_str(), iter->second.strProcessPath.c_str());
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

/*
[
    {
        "weight":1,
        "time":1595485514,
        "attack_ip":"127.0.0.1",
        "destination_ip":"127.0.0.1",
        "open_port":80,
        "redirect_ip":"127.0.0.1",
        "redirect_port":80
    },
    {
        "weight":1,
        "time":1595485514,
        "attack_ip":"127.0.0.2",
        "destination_ip":"127.0.0.2",
        "open_port":8080,
        "redirect_ip":"127.0.0.2",
        "redirect_port":8080
    }
]
*/

int BuildupOpenPortJson(std::vector<pOpenPort>& loginfo, std::string &str_json) {

    cJSON *root = cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();
    if ((array_data == NULL) || (root == NULL)) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root,"alert", array_data);
    std::vector<pOpenPort>::iterator iter;
    for (iter = loginfo.begin(); iter != loginfo.end(); iter++) {
    
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"weight", cJSON_CreateNumber(iter->weight));
        cJSON_AddItemToObject(mem,"time", cJSON_CreateNumber(iter->time));
        cJSON_AddItemToObject(mem,"attack_ip", cJSON_CreateString(iter->attack_ip.c_str()));
        cJSON_AddItemToObject(mem,"destination_ip", cJSON_CreateString(iter->destination_ip.c_str()));
        cJSON_AddItemToObject(mem,"open_port", cJSON_CreateNumber(iter->open_port));
        cJSON_AddItemToObject(mem,"redirect_ip", cJSON_CreateString(iter->redirect_ip.c_str()));
        cJSON_AddItemToObject(mem,"redirect_port", cJSON_CreateNumber(iter->redirect_port));
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int Builaddperipherals(std::vector<USB_INFO>& loginfo, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "data", array_data);
    
    std::vector<USB_INFO>::iterator iter;
    for (iter = loginfo.begin(); iter != loginfo.end(); iter++) {
        
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddItemToObject(mem,"peripheral_eid", cJSON_CreateString(iter->eid.c_str()));
        cJSON_AddItemToObject(mem,"peripheral_name", cJSON_CreateString(iter->name.c_str()));
        cJSON_AddItemToObject(mem,"peripheral_intro", cJSON_CreateString(iter->intro.c_str()));
        cJSON_AddItemToObject(mem,"peripheral_type", cJSON_CreateString(iter->type.c_str()));
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}


int BuildSysLogDnsJson(SYLOG_DNS_LOG conf, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddStringToObject(root, "uid", conf.uid.c_str());
    cJSON_AddNumberToObject(root, "p_id", conf.p_id);
    cJSON_AddStringToObject(root, "p_dir", conf.p_dir.c_str());
    cJSON_AddStringToObject(root, "domain_name", conf.domain_name.c_str());
    cJSON_AddStringToObject(root, "res_ip", conf.res_ip.c_str());
    cJSON_AddNumberToObject(root, "time", conf.time);
    cJSON_AddNumberToObject(root, "log_type", conf.log_type);
    cJSON_AddStringToObject(root, "hash", conf.hash.c_str());
    
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildSysLogNetJson(SYSLOG_NET_LOG conf, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddStringToObject(root, "uid", conf.uid.c_str());
    cJSON_AddNumberToObject(root, "p_id", conf.p_id);
    cJSON_AddStringToObject(root, "p_dir", conf.p_dir.c_str());
    cJSON_AddStringToObject(root, "source_ip", conf.source_ip.c_str());
    cJSON_AddNumberToObject(root, "source_port", conf.source_port);
    cJSON_AddStringToObject(root, "res_ip", conf.res_ip.c_str());
    cJSON_AddNumberToObject(root, "rs_port", conf.rs_port);
    cJSON_AddNumberToObject(root, "proto", conf.proto);
    cJSON_AddNumberToObject(root, "time", conf.time);
    cJSON_AddNumberToObject(root, "log_type", conf.log_type);
    cJSON_AddStringToObject(root, "hash", conf.hash.c_str());
    cJSON_AddNumberToObject(root, "res_port_status", 1);
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildProcessEDRJson(const EDRPROCESS_LOG &conf, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddStringToObject(root, "uid", conf.uid.c_str());
    cJSON_AddStringToObject(root, "hash", conf.hash.c_str());
    cJSON_AddNumberToObject(root, "p_id", conf.p_id);
    cJSON_AddStringToObject(root, "p_dir", conf.p_dir.c_str());
    if (conf.p_param.empty()) {
        cJSON_AddStringToObject(root, "p_param", conf.p_dir.c_str());
    } else {
        cJSON_AddStringToObject(root, "p_param", conf.p_param.c_str());
    }
    cJSON_AddStringToObject(root, "pp_hash", conf.pp_hash.c_str());
    cJSON_AddNumberToObject(root, "pp_id", conf.pp_id);
    cJSON_AddStringToObject(root, "pp_dir", conf.pp_dir.c_str());
    cJSON_AddStringToObject(root, "pp_param", conf.pp_param.c_str());
    cJSON_AddNumberToObject(root, "log_type", conf.log_type);
    cJSON_AddNumberToObject(root, "time", conf.time);
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}


int BuildCloseTask(const int &taskId, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddNumberToObject(root, "tasklist", taskId);    
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;  
}

int BuildHttpLogDnsJson(std::vector<SYLOG_DNS_LOG> conf, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "list", array_data);
    
    std::vector<SYLOG_DNS_LOG>::iterator iter;
    for (iter = conf.begin(); iter != conf.end(); iter++) {
        
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddStringToObject(mem, "uid", iter->uid.c_str());
        cJSON_AddNumberToObject(mem, "p_id", iter->p_id);
        cJSON_AddStringToObject(mem, "p_dir", iter->p_dir.c_str());
        cJSON_AddStringToObject(mem, "domain_name", iter->domain_name.c_str());
        cJSON_AddStringToObject(mem, "res_ip", iter->res_ip.c_str());
        cJSON_AddNumberToObject(mem, "time", iter->time);
        cJSON_AddNumberToObject(mem, "log_type", iter->log_type);
        cJSON_AddStringToObject(mem, "hash", iter->hash.c_str());
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildHttpLogNetJson(std::vector<SYSLOG_NET_LOG> conf, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "list", array_data);
    
    std::vector<SYSLOG_NET_LOG>::iterator iter;
    for (iter = conf.begin(); iter != conf.end(); iter++) {
        
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddStringToObject(mem, "uid", iter->uid.c_str());
        cJSON_AddNumberToObject(mem, "p_id", iter->p_id);
        cJSON_AddStringToObject(mem, "p_dir", iter->p_dir.c_str());
        cJSON_AddStringToObject(mem, "source_ip", iter->source_ip.c_str());
        cJSON_AddNumberToObject(mem, "source_port", iter->source_port);
        cJSON_AddStringToObject(mem, "res_ip", iter->res_ip.c_str());
        cJSON_AddNumberToObject(mem, "rs_port", iter->rs_port);
        cJSON_AddNumberToObject(mem, "proto", iter->proto);
        cJSON_AddNumberToObject(mem, "time", iter->time);
        cJSON_AddNumberToObject(mem, "log_type", iter->log_type);
        cJSON_AddStringToObject(mem, "hash", iter->hash.c_str());
        cJSON_AddNumberToObject(mem, "res_port_status", 1);
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildHttpProcessEDRJson(std::vector<EDRPROCESS_LOG> &conf, std::string &str_json) {

    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "list", array_data);
    
    std::vector<EDRPROCESS_LOG>::iterator iter;
    for (iter = conf.begin(); iter != conf.end(); iter++) {
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddStringToObject(mem, "uid", iter->uid.c_str());
        cJSON_AddStringToObject(mem, "hash", iter->hash.c_str());
        cJSON_AddNumberToObject(mem, "p_id", iter->p_id);
        cJSON_AddStringToObject(mem, "p_dir", iter->p_dir.c_str());
        cJSON_AddStringToObject(mem, "p_param", iter->p_dir.c_str());
        cJSON_AddStringToObject(mem, "pp_hash", iter->pp_hash.c_str());
        cJSON_AddNumberToObject(mem, "pp_id", iter->pp_id);
        cJSON_AddStringToObject(mem, "pp_dir", iter->pp_dir.c_str());
        cJSON_AddStringToObject(mem, "pp_param", iter->pp_param.c_str());
        cJSON_AddNumberToObject(mem, "log_type", iter->log_type);
        cJSON_AddNumberToObject(mem, "time", iter->time);
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildLinuxDirProcessJson(std::vector<LinuxDirProc> &conf, std::string &str_json) {

    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "list", array_data);
    
    std::vector<LinuxDirProc>::iterator iter;
    for (iter = conf.begin(); iter != conf.end(); iter++) {
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddStringToObject(mem, "dir", iter->dir.c_str());
        cJSON_AddStringToObject(mem, "hash", iter->hash.c_str());
        cJSON_AddStringToObject(mem, "introduce", iter->introduce.c_str());
        cJSON_AddStringToObject(mem, "copyright", iter->copyright.c_str());
        cJSON_AddItemToArray(array_data, mem);
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildJsonByString(std::vector<std::string> &vecData, std::string &str_json) {
    cJSON *root =  cJSON_CreateObject();
    cJSON *array_data = cJSON_CreateArray();

    if (root == NULL || array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "list", array_data);
    
    std::vector<std::string>::iterator iter;
    for (iter = vecData.begin(); iter != vecData.end(); iter++) {
        cJSON *mem = cJSON_Parse(iter->c_str());
        if (mem) {
            cJSON_AddItemToArray(array_data, mem);
        }
    }

    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildSysLogSSHJson(SYLOG_SSH_LOG conf, std::string &str_json) {
     cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddStringToObject(root, "ip", conf.ip.c_str());
    cJSON_AddStringToObject(root, "username", conf.username.c_str());
    cJSON_AddStringToObject(root, "type", conf.type.c_str());
    cJSON_AddNumberToObject(root, "status", conf.status);
    cJSON_AddNumberToObject(root, "log_type", conf.log_type);
    cJSON_AddNumberToObject(root, "time", conf.time);
    char* json_print = cJSON_PrintUnformatted(root);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root) cJSON_Delete(root);
    return 0;
}

int BuildResLogJson(RES_LOG conf, std::string &str_json) {

    cJSON *root_top =  cJSON_CreateObject();
    if (root_top == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or root_top failed.", __LINE__, __FUNCTION__);
        return -1;
    }

     cJSON *root =  cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root_top, "info", root);

    cJSON_AddStringToObject(root, "hd_size", conf.hd_size.c_str());
    cJSON_AddStringToObject(root, "hd_usage", conf.hd_usage.c_str());
    cJSON_AddStringToObject(root, "cpu_number", conf.cpu_number.c_str());
    cJSON_AddStringToObject(root, "cpu_usage", conf.cpu_usage.c_str());
    cJSON *array_data = cJSON_CreateArray();
    if (array_data == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or cJSON_CreateArray failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "cpu_tops", array_data);

    for (int i = 0; i<5; i++) {
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddStringToObject(mem, "id", conf.cpu_tops[i].id.c_str());
        cJSON_AddStringToObject(mem, "dir", conf.cpu_tops[i].dir.c_str());
        cJSON_AddStringToObject(mem, "hash", conf.cpu_tops[i].hash.c_str());
        cJSON_AddStringToObject(mem, "cpu_usage",conf.cpu_tops[i].cpu_usage.c_str());
        cJSON_AddStringToObject(mem, "mem_size", conf.cpu_tops[i].mem_size.c_str());
        cJSON_AddStringToObject(mem, "user", conf.cpu_tops[i].user.c_str());
        cJSON_AddItemToArray(array_data, mem);
    }
    cJSON_AddStringToObject(root, "mem_size", conf.mem_size.c_str());
    cJSON_AddStringToObject(root, "mem_usage", conf.mem_usage.c_str());

    cJSON *array_data_mem = cJSON_CreateArray();
    if (array_data_mem == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or array_data_mem failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "mem_tops", array_data_mem);

    for (int i = 0; i<5; i++) {
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddStringToObject(mem, "id", conf.mem_tops[i].id.c_str());
        cJSON_AddStringToObject(mem, "dir", conf.mem_tops[i].dir.c_str());
        cJSON_AddStringToObject(mem, "hash", conf.mem_tops[i].hash.c_str());
        cJSON_AddStringToObject(mem, "cpu_usage",conf.mem_tops[i].cpu_usage.c_str());
        cJSON_AddStringToObject(mem, "mem_size", conf.mem_tops[i].mem_size.c_str());
        cJSON_AddStringToObject(mem, "user", conf.mem_tops[i].user.c_str());
        cJSON_AddItemToArray(array_data_mem, mem);
    }  

    cJSON *self = cJSON_CreateObject();
    if (self == NULL) {
        LOG_ERROR("[ %d ] [ %s ] cJSON_CreateObject or self failed.", __LINE__, __FUNCTION__);
        return -1;
    }
    cJSON_AddItemToObject(root, "self", self);
    cJSON_AddStringToObject(self, "mem_size", conf.self_mem_size.c_str());
    cJSON_AddStringToObject(self, "cpu_usage", conf.self_cpu_usage.c_str());


    char* json_print = cJSON_PrintUnformatted(root_top);
    if (json_print) {
        str_json = std::string(json_print);
        free(json_print);
    }
    if (NULL != root_top) cJSON_Delete(root);
    return 0;
}


}
