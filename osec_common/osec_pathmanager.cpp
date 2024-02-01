#include "osec_pathmanager.h"
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cassert>
#include "utils/file_utils.h"
#include "osec_common/socket_osec.h"
#include "common/socket/socket_process_info.h"

namespace PathManager {

std::string GetInstallPath() {
    std::string install_path = "/opt/osec/";
    return install_path;
}

std::string GetLogPath() {
    std::string log_path = "/opt/osec/log/";
    return log_path;
}

std::string GetLogConfigPath() {
    std::string log_config_path = GetLogPath() + "log.conf";
    return log_config_path;
}


std::string GetInnerTXProcessPath(long process_name) {
    std::string str_interact_path = GetInstallPath();
    return str_interact_path;
}

std::string GetFrontUIReconnectPath(){
    return GetInnerTXProcessPath(OSEC_FRONT_UI_ID);
}

std::string GetNetFileReconnectPath() {
    return GetInnerTXProcessPath(OSEC_FILE_NET_AGENT_ID);
}

std::string GetNetMangaerReconnectPath(){
    return GetInnerTXProcessPath(OSEC_BUSINESS_NET_AGENT_ID);
}

std::string GetCommonGNReconnectPath(){
    return GetInnerTXProcessPath(OSEC_BACKEND_ID);
}

std::string GetProcessPrivateDataPath(long process_name) {
    std::string private_data_path = GetInnerTXProcessPath(process_name);
    return private_data_path;
}

std::string GetProcessPidPath(long process_name) {
    std::string pid_path = GetInnerTXProcessPath(process_name);
    pid_path += ".";
    pid_path += process_name;
    pid_path += "_pid";
    
    return pid_path;
}

std::string GetActivationPath() {
    std::string strConfigPath = GetInnerTXProcessPath(OSEC_BACKEND_ID) + "activation_info.ini";
    return strConfigPath;
}

std::string GetDriverPath() {
    std::string strDriverPath = GetInstallPath();
    return strDriverPath;
}

std::string GetDriverConfigPath() {
    std::string strConfigPath = GetInnerTXProcessPath(OSEC_BACKEND_ID) + "osec_kernel.conf";
    return strConfigPath;
}

std::string GetClientServerNetInfoPath() {
    std::string str_net_config = GetInnerTXProcessPath(OSEC_BUSINESS_NET_AGENT_ID) + "net_info.ini";
    return str_net_config;
}

std::string GetPolicyDataPath() {
    std::string str_policy_data = GetInnerTXProcessPath(OSEC_BUSINESS_NET_AGENT_ID) + "policy_history.dat";
    return str_policy_data;
}

std::string GetFileServerNetInfoPath() {
    std::string str_s3_server = GetInnerTXProcessPath(OSEC_FILE_NET_AGENT_ID) + "file_server.ini";
    return str_s3_server;
}

std::string GetDonwloadTmpFilePath() {
    std::string str_download_tmp_file_path = GetInstallPath() + "UITX/download/";
    return str_download_tmp_file_path;
}

std::string GetUploadTmpFilePath() {
    std::string str_download_tmp_file_path = GetInstallPath() + "UITX/upload/";
    return str_download_tmp_file_path;
}

std::string GetUninstallSettingPath() {
    std::string str_tmp_path = GetInstallPath() + "UITX/.OSECdksjuninstall";
    return str_tmp_path;
}

std::string GetVersionPath() {
    std::string str_version_path = GetInstallPath() + "TXdata/version.dat";
    return str_version_path;
}
}
