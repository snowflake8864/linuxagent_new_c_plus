#ifndef BACKEND_NET_AGENT_DATA_OPERATION_PARSE_JSON_H_
#define BACKEND_NET_AGENT_DATA_OPERATION_PARSE_JSON_H_

#include <stdlib.h>
#include <string.h>
#include "osec_common/global_message.h"
#include "common/json/cJSON.h"

namespace parse_json {
void SetServerIp(const std::string& Ip, const std::string& port);
int ParaseOnlineJson(const std::string &strData, std::string &str_token);

int ParsePolicyInfo(const std::string &strData, const std::string &strKey, std::string &strValue);
int ParseAllTaskInfo(const std::string &strData, TASK_BASE &vecNotifyTask);
int ParseClientLevelFromNotifyTask(const std::string &strData, int &nLevel);
int ParaseProcessWhite(const std::string &strData, std::map<std::string, std::string> &mapProcessInfo);
int ParaseProtectDir(const std::string &strData, std::vector<POLICY_PROTECT_DIR> &vecProtectDir);
int ParaseConfJson(const std::string &str_json, CONFIG_INFO &conf);
int ParaseUpdateJson(const std::string &str_json, POLICY_UPDATE &update);
int ParaseDirView(const std::string &str_json, std::vector<DIR_VIEW> &vecDirView);
int ParaseSingleProcessModule(const std::string &str_json, std::vector<POLICY_SINGLE_PROCESS_SO> &vecSingleSo);
int ParaseExiportProtect(const std::string &str_json, std::vector<POLICY_EXIPOR_PROTECT> &vecExiport);
int ParasePolicyProcessModule(const std::string &str_json, std::vector<POLICY_PROCESS_MODULE_SO> &vecExiport);
int ParasePolicyVirtual(const std::string &str_json, std::vector<PORT_REDIRECT> &lstPort_policy);
int ParaseNetWhiteBlack(const std::string &str_json, std::vector<NET_PROTECT_IP> &lstPolicy, const int type);
int ParaseNetBlockList(const std::string &str_json, std::vector<NETBLOCK> &lstPolicy);
int ParaseUSBInfoPolicy(const std::string &str_json, std::vector<USB_INFO> &lstPolicy, const int nAllow);
int ParaseSampleInfo(const std::string &str_json, std::vector<SAMPLE_INFO> &lstSample);
int ParaseSysLogConfJson(const std::string &str_json, SYSLOG_INFO &conf);
int ParaseGettrustdirJson(const std::string &str_json, std::vector<GlobalTrusrDir> &lsttrustdir);
}

#endif /* BACKEND_NET_AGENT_DATA_OPERATION_PARSE_JSON_H_ */
