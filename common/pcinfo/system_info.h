#ifndef PC_INFO_SYSTEM_INFO_H
#define PC_INFO_SYSTEM_INFO_H

#include <string>

namespace SystemInfo {
    enum LocalInfoType {
        kLocalSocIDInfo = 0,
        kLocalHardSNInfo = 1,
        kLocalOSNameInfo = 2,
        kLocalProducerInfo = 3,
        kLocalInfoMax
    };
    int GetLocalInfo(LocalInfoType type, std::string &local_info);
    int DoGetLocalInfo(const std::string str_type_info, LocalInfoType type, std::string &local_info);
}

#endif /* PC_INFO_SYSTEM_INFO_H */