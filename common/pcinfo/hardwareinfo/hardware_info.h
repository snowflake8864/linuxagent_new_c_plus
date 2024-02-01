#ifndef PCINFO_HARDWARE_INFO_H_
#define PCINFO_HARDWARE_INFO_H_

#include <map>
#include <ostream>
#include <string>

struct BaseboardInfo {
    std::string manufacturer;
    std::string product_name;
    std::string version;
    std::string serial_number;
    friend std::ostream& operator<<(std::ostream& out,
                                    const BaseboardInfo& baseboard_info) {
        out << "BaseboardInfo:" << std::endl
            << "\tmanufacturer:" << baseboard_info.manufacturer << std::endl
            << "\tproduct_name:" << baseboard_info.product_name << std::endl
            << "\tversion:" << baseboard_info.version << std::endl
            << "\tserial_number:" << baseboard_info.serial_number << std::endl;
        return out;
    }
};

struct CpuInfo {
    std::string type;
    std::string family;
    std::string manufacturer;
    std::string cpuid;    // CPUID
    std::string version;  // e.g Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz
    friend std::ostream& operator<<(std::ostream& out,
                                    const CpuInfo& cpu_info) {
        out << "CpuInfo:" << std::endl
            << "\ttype:" << cpu_info.type << std::endl
            << "\tfamily:" << cpu_info.family << std::endl
            << "\tmanufacturer:" << cpu_info.manufacturer << std::endl
            << "\tcpuid:" << cpu_info.cpuid << std::endl
            << "\tversion:" << cpu_info.version << std::endl;
        return out;
    }
};

struct SystemInfo {
    std::string manufacturer;
    std::string product_name;
    std::string version;
    std::string serial_number;
    std::string uuid;
    friend std::ostream& operator<<(std::ostream& out,
                                    const SystemInfo& system_info) {
        out << "SystemInfo:" << std::endl
            << "\tmanufacturer:" << system_info.manufacturer << std::endl
            << "\tproduct_name:" << system_info.product_name << std::endl
            << "\tserial:" << system_info.serial_number << std::endl
            << "\tuuid:" << system_info.uuid << std::endl;
        return out;
    }
};

struct HardwareInfo {
    std::map<std::string, CpuInfo> cpu_infos;
    BaseboardInfo baseboard_info;
    SystemInfo system_info;
    friend std::ostream& operator<<(std::ostream& out,
                                    const HardwareInfo& hardware_info) {
        std::map<std::string, CpuInfo>::const_iterator cpu_infos_it;
        for (cpu_infos_it = hardware_info.cpu_infos.begin();
             cpu_infos_it != hardware_info.cpu_infos.end(); ++cpu_infos_it) {
            out << cpu_infos_it->second;
        }
        out << hardware_info.baseboard_info
            << hardware_info.system_info;
        return out;
    }
};

#endif  /* PCINFO_HARDWARE_INFO_H_ */
