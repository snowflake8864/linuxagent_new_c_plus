#ifndef OSEC_PATHMANAGER_H_
#define OSEC_PATHMANAGER_H_

#include <string>

namespace PathManager {

std::string GetInstallPath();
std::string GetLogPath();
std::string GetLogConfigPath();
std::string GetDataTransferExecPath();
std::string GetFrontUIExecPath();
std::string GetNetFileExecPath();
std::string GetNetMangaerExecPath();
std::string GetCommonGNExecPath();
std::string GetInnerTXProcessPath(long process_name);
std::string GetFrontUIReconnectPath();
std::string GetNetFileReconnectPath();
std::string GetNetMangaerReconnectPath();
std::string GetCommonGNReconnectPath();
std::string GetProcessPrivateDataPath(long process_name);
std::string GetProcessPidPath(long process_name);
std::string GetClientServerNetInfoPath();
std::string GetPolicyDataPath();
std::string GetFileServerNetInfoPath();
std::string GetDonwloadTmpFilePath();
std::string GetUploadTmpFilePath();    
std::string GetUninstallSettingPath() ;
std::string GetActivationPath();
std::string GetDriverPath();
std::string GetDriverConfigPath();
std::string GetVersionPath();
int getLocalIPMac(std::string &ip, std::string &mac);

}

#endif /* PATHMANAGER_H_ */
