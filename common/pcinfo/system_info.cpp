#include "pcinfo/system_info.h"
#include <string.h>
#include "ini_parser.h"
#include "log/log.h"

#define CLIENT_INFO_FILE_PATH "/etc/abc"

#define SOCK_FILE_KEY_CN "标识码"
#define SOCK_FILE_KEY_EN "ID"
#define HARD_FILE_KEY_CN "硬盘序列号"
#define HARD_FILE_KEY_EN "HDSerial"
#define OS_NAME_KEY_CN   "操作系统名称"
#define OS_NAME_KEY_EN   "Name"
#define PRODUCER_KEY_CN  "生产者"
#define PRODUCER_KEY_EN  "Producer"

std::string system_info_cn[] = {
    SOCK_FILE_KEY_CN,
    HARD_FILE_KEY_CN,
    OS_NAME_KEY_CN,
    PRODUCER_KEY_CN
};

std::string system_info_en[] = {
    SOCK_FILE_KEY_EN,
    HARD_FILE_KEY_EN,
    OS_NAME_KEY_EN,
    PRODUCER_KEY_EN
};

namespace SystemInfo {

int GetLocalInfo(LocalInfoType type, std::string &local_info) {
    switch(type) {
        case kLocalSocIDInfo:
            return DoGetLocalInfo("sock id", type, local_info);
        case kLocalHardSNInfo:
            return DoGetLocalInfo("hard sn", type, local_info);
        case kLocalOSNameInfo:
            return DoGetLocalInfo("computer os name", type, local_info);
        case kLocalProducerInfo:
            return DoGetLocalInfo("producer name", type, local_info);
        default:
            return -1;
    }
    return -1;
}

int DoGetLocalInfo(const std::string str_type_info, LocalInfoType type, std::string &local_info) {
    FILE *fp = NULL;
    if ((fp = fopen(CLIENT_INFO_FILE_PATH, "r")) == NULL) {
        LOG_ERROR("open config file[%s] failed.", CLIENT_INFO_FILE_PATH);
        return -1;
    }
    int rtn = -1;
    while (feof(fp) == 0) {
        char buf[128] = {0};
        memset(buf, '\0', sizeof(buf));
        if (fgets(buf, sizeof(buf), fp) == NULL) {
            LOG_ERROR("fgets file:%s, errno:%d, strerr:%s\n", CLIENT_INFO_FILE_PATH, errno, strerror(errno));
            break;
        }
        if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n' || buf[0] == '\0') {
            continue;
        }
        if (strstr(buf, system_info_cn[type].c_str())) {
            std::vector<std::string> str_vector;
            std::string str_buf = buf;
            if (str_buf.find("=") != std::string::npos) {
                string_utils::Split(str_vector, str_buf, "=");
            } else if (str_buf.find(":") != std::string::npos) {
                string_utils::Split(str_vector, str_buf, ":");
            } else if (str_buf.find("：") != std::string::npos) {
                string_utils::Split(str_vector, str_buf, "：");
            } else {
                LOG_ERROR("can not get client %s.", str_type_info.c_str());
            }
            if (str_vector.size() == 2) {
                local_info = str_vector[1];
                LOG_INFO("%s: %s", str_type_info.c_str(), local_info.c_str());
                rtn = 0;
                break;
            } else {
                LOG_ERROR("can not get client %s, str_vector.size != 2.", str_type_info.c_str());
            }
        } else if (strstr(buf, system_info_en[type].c_str())) {
            std::vector<std::string> str_vector;
            std::string str_buf = buf;
            if (str_buf.find("=") != std::string::npos) {
                string_utils::Split(str_vector, str_buf, "=");
            }
            if (str_vector.size() == 2) {
                local_info = str_vector[1];
                LOG_INFO("%s: %s", str_type_info.c_str(), local_info.c_str());
                rtn = 0;
                break;
            } else {
                LOG_ERROR("can not get client %s, str_vector.size != 2.", str_type_info.c_str());
            }
        }
    }
    if (fp != NULL) fclose(fp);
    return rtn;
}

}
