#ifndef BACKEND_NET_AGENT_DATA_OPERATION_BUILD_JSON_H_
#define BACKEND_NET_AGENT_DATA_OPERATION_BUILD_JSON_H_

#include <stdlib.h>
#include <vector>
#include "osec_common/global_message.h"
#include "common/pcinfo/pc_base_info.h"

/*
{
	"proclist"：”
	proclist
	default {##
		进程 ID 进程用户名 进程路径参数 进程 hash
		1002 user1 / usr / libexec / ibus - x11--kill - daemon 0 ca175b9c0f726a831d895e269332461
		1003 user1 / usr / bin / pulseaudio--start--log - target = syslog 0 ca175b9c0f726a831d895e269332461
	}”
}

{
	"conf"：”
	conf
	default {##
		配置信息## serveripport 192.168 .1 .1: 80## logsent ON / OFF## proc - protect ON / OFF 进程白名单是否开启， 如果开启， 没有在白名单内部的进程无法启动， 开启系统处在进程保护模式， 关闭系统处在
		进程监控模式## file - protect ON / OFF 文件防篡改保护是否开启## comtime 60 获取服务器命令时间间隔， 单位秒## scanproctime 300 扫描进程时间间隔， 单位秒## scanfiletime 300 扫描文件 hash 变化时间间隔， 单位秒。## sendproclisttime 1800 定时发送系统进程列表到服务器## senddirlisttime 3600 定时发送进程列表到服务器
	}”
}

请求提交方法： {“
	dir”: “dir
	default {##
		格式 默认权限 用户 组 大小 创建时间 修改时间 安全权限 可写入文件类型 hash## 权限 RWX R 可读 W 可写 X 可执行， 可写包含可以写入新文件## 可写入文件类型 如果目录可写， 同时可以配置写入允许文件类型， jpeg | jpg | gif， 配置为不可写时候， 该字段写 NULL /
		var / www drwxr - xr - x jeno staff 224 2012 / 09 / 24 17: 10: 17 2012 / 09 / 24 17: 10: 17 RWX jpeg | jpg | gif NULL Makefile drwxr - xr - x jeno staff 2234 2012 / 09 / 24 17: 10: 17 2012 / 09 / 24 17: 10: 17 RX NULL NULL
		framework.py rwxr - xr - x jeno staff 214 2012 / 09 / 24 17: 10: 17 2012 / 09 / 24 17: 10: 17 RWX jpg | gif edae5d16520de6edasef707cdc968543 /
			var / www / Makefile drwxr - xr - x jeno staff 224 2012 / 09 / 24 17: 10: 17 2012 / 09 / 24 17: 10: 17 RWX NULL
		conf.py rwxr - xr - x jeno staff 214 2012 / 09 / 24 17: 10: 17 2012 / 09 / 24 17: 10: 17 RWX jpg | gif eeafd16520de6edasef707cdc968543
		幻甲 API 接口说明
	}”
}

{“
	"alert”: “alert
	default {##
		告警级别 0： 普通， 1： 重要， 2： 严重
		幻甲 API 接口说明## 时间戳## 类型（ 0： 文件被修改， 1： 文件被删除， 2： 文件新建， 3： 文件修改被阻断， 4: 文件删除被阻断， 5： 文件新建被阻断。）(6: 进程创建非白名单， 7： 进程创建被阻断）## 参数## 0 号类型 告警级别 告警时间 告警类型 文件路径 文件 hash 0 2019 - 9 - 22 - 09: 25 0 /
			var / www / index.php abce5d16520de693a3fe707cdc968562## 1 号类型 告警级别 告警时间 告警类型 文件路径 0 2019 - 9 - 22 - 09: 25 1 /
			var / www / index.php## 2 号类型 告警级别 告警时间 告警类型 文件路径 文件 hash 2 2019 - 9 - 22 - 09: 25 2 /
			var / www / index.php abce5d16520de693a3fe707cdc968562## 3 号类型 告警级别 告警时间 告警类型 文件路径 文件 hash 2 2019 - 9 - 22 - 09: 25 3 /
			var / www / index.php abce5d16520de693a3fe707cdc968562## 4 号类型 告警级别 告警时间 告警类型 文件路径 文件 hash 2 2019 - 9 - 22 - 09: 25 4 /
			var / www / index.php abce5d16520de693a3fe707cdc968562## 5 号类型 告警级别 告警时间 告警类型 文件路径 文件 hash 2 2019 - 9 - 22 - 09: 25 5 /
			var / www / index.php abce5d16520de693a3fe707cdc968562## 6 号类型 告警级别 告警时间 告警类型 进程路径 进程 hash 2 2019 - 9 - 22 - 09: 25 6 /
			var / bin / ps abce5d16520de693a3fe707cdc968562## 7 号类型 告警级别 告警时间 告警类型 进程路径 进程 hash 2 2019 - 9 - 22 - 09: 25 7 /
			var / bin / ps abce5d16520de693a3fe707cdc968562
		}”
}
 */

#define POLICY_PROCESS_JSON "/opt/osec/policy_procss.json"
#define POLICY_DIR_JSON     "/opt/osec/policy_dir.json"

namespace build_json {

int BuildAuthOnlineJson(const BASE_ONLINE &base_online, std::string &strData);
int BuildConfJson(CONFIG_INFO conf, std::string &str_json);
int BuildRequestJson(const std::string &str_uid, const std::string &auth, std::string str_json);
int BuildProcessListJson(std::vector<Audit_PROCESS>& processinfo, std::string &str_json, const int &nfinish =2);
int BuildDirInfoJson(std::vector<FILE_INFO>& dirinfo, std::string &str_json);
int BuildAlertLogJson(std::vector<LOG_INFO>& loginfo, std::string &str_json);
int BuildBusinessPortJson(std::vector<PORT_BUSINESS_LIST>& loginfo, std::string &str_json);
int BuildBusinessPortJson_ex(std::map<std::string, PORT_BUSINESS_LIST>& loginfo, std::string &str_json);
int BuildupOpenPortJson(std::vector<pOpenPort>& loginfo, std::string &str_json);

int Builaddperipherals(std::vector<USB_INFO>& loginfo, std::string &str_json);
int write_json_file(const std::string& str_file, const std::string& str_json);
int read_json_file(const std::string& str_file, std::string& str_json);
//int BuildSampleJson(const SAMPLE_INFO& sample_info, std::string& str_json);
int BuildSysLogDnsJson(SYSLOG_DNS_LOG conf, std::string &str_json);
int BuildSysLogNetJson(SYSLOG_NET_LOG conf, std::string &str_json);
int BuildAutoProcessListJson(std::vector<Audit_PROCESS> &processinfo, std::string &str_json);
int BuildCloseTask(const int &taskId, std::string &str_json);
int BuildProcessEDRJson(const EDRPROCESS_LOG &conf, std::string &str_json);

int BuildHttpLogDnsJson(std::vector<SYLOG_DNS_LOG> conf, std::string &str_json);
int BuildHttpLogNetJson(std::vector<SYSLOG_NET_LOG> conf, std::string &str_json);
int BuildHttpProcessEDRJson(std::vector<EDRPROCESS_LOG> &conf, std::string &str_json);
int BuildLinuxDirProcessJson(std::vector<LinuxDirProc> &conf, std::string &str_json);

int BuildJsonByString(std::vector<std::string> &vecData, std::string &str_json);
int BuildSysLogSSHJson(SYLOG_SSH_LOG conf, std::string &str_json);
int BuildResLogJson(RES_LOG conf, std::string &str_json);
int BuildSelfProtectJson(struct Audit_SelfProtect &info, std::string &str_json); 
}

#endif /* BACKEND_NET_AGENT_DATA_OPERATION_BUILD_JSON_H_ */
