#ifndef COMMON_GLOBAL_CONFIG_HPP_
#define COMMON_GLOBAL_CONFIG_HPP_

#define INSTALL_PATH  "/opt/osec/"

//=================================================
#define SECTION_CLIENTINFO      "clientinfo"
#define KEY_CLIENT_MID          "mid"
#define KEY_CLIENT_AUDIT_CLEAN  "logclean"
#define KEY_CLIENT_NET_TYPE     "net_type"
#define KEY_CLIENT_LEVEL        "client_level"
#define SECTION_SERVERINFO      "serverinfo"
#define KEY_SERVER_IP           "server_ip"
#define KEY_SERVER_PORT         "server_port"
#define KEY_VERSION             "version"
#define KEY_USER_ID             "user_id"

#define KEY_serveripport "serveripport"
#define KEY_logipport    "logipport"
#define KEY_logproto "logproto"
#define KEY_logsent "logsent"
#define KEY_proc_protect "proc_protect"
#define KEY_file_protect "file_protect"
#define KEY_comtime "crontime"
#define KEY_extortion "extortion_protect"
#define KEY_proc_switch "proc_switch"
#define KEY_module_switch "module_switch"
#define KEY_file_switch "file_switch"

#define KEY_extortion_switch "extortion_switch"
#define KEY_usb_switch "usb_switch"
#define KEY_open_port_switch "open_port_switch"
#define KEY_usb_protect "usb_protect"
//login
#define LOGIN_SUCCESS                0                          //登录成功
#define LOGIN_FAIL                   1                          //登录失败

#define AUDIT_BEHAVIOR_TYPE_MAX                             58                      //最大值

#define AUDIT_RESULT_SUCCESS                            1                       //操作成功
#define AUDIT_RESULT_FAILED                             2                       //操作失败

#define FILE_VIEW_TYPE_CLOSE                            0                       // 关闭标签文件
#define FILE_VIEW_TYPE_OPEN                             1                       // 打开标签文件

#define AUDIT_DETAIL_KEY_CONTENT                        "content"               //审计详情key

#define RESPONSE_RESULT_SUCCESS                         "success"               //返回成功

#endif /* COMMON_GLOBAL_CONFIG_HPP_ */
