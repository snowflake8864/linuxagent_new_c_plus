#include "pc_soc_id.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include "md5sum.h"
#include "utils/file_utils.h"
#include "utils/string_utils.hpp"
#include "json/cJSON.h"
#include "log/log.h"
#include "hardwareinfo/dmidecode.h"
#include "dependlibs/libudev/include/libudev.h"

static bool IsValidHardwareInfo(const HardwareInfo& hardware_info) {
    if (hardware_info.cpu_infos.empty()) {
        return false;
    }
    bool is_empty_cpuid = true;
    std::map<std::string, CpuInfo>::const_iterator it;
    for (it = hardware_info.cpu_infos.begin(); it != hardware_info.cpu_infos.end(); ++it) {
        if (!it->first.empty()) {
            is_empty_cpuid = false;
            break;
        }
    }
    if (is_empty_cpuid) {
        return false;
    }
    if (hardware_info.system_info.uuid.empty() && hardware_info.system_info.serial_number.empty()) {
        return false;
    }
    return true;
}


static std::string GetHardDiskSNWithUDEV(const char* dev) {
    std::string str_serial_id;
    struct udev *ud = udev_new();
    if (NULL == ud) {
        LOG_ERROR("get hard disk serial number with udev failed.");
    } else {
        struct stat statbuf;
        if (0 != stat(dev, &statbuf)) {
            LOG_ERROR("stat %s failed, because: %s[%d].", dev, strerror(errno), errno);
        } else {
            struct udev_device *device = udev_device_new_from_devnum(ud, 'b', statbuf.st_rdev);
            if (NULL == device) {
                LOG_ERROR("get hard disk serial number error, udev_device_new_from_devnum[%s] failed.", dev);
            } else {
                struct udev_list_entry *entry = udev_device_get_properties_list_entry(device);
                while (NULL != entry) {
                    if (0 == strcmp(udev_list_entry_get_name(entry), "ID_FS_UUID")) {
                        str_serial_id = udev_list_entry_get_value(entry);
                    }
                    if (0 == strcmp(udev_list_entry_get_name(entry), "ID_SERIAL")) {
                        str_serial_id = udev_list_entry_get_value(entry);
                        break;
                    }
                    entry = udev_list_entry_get_next(entry);
                }
                udev_device_unref(device);
            }
        }
        (void)udev_unref(ud);
    }
    return str_serial_id;
} 

static std::string GetHardDiskSerialNumber() {
    std::string str_serial_id;
    FILE *fp = fopen ("/etc/mtab", "r");
    if (fp == NULL) {
        LOG_ERROR("get hard disk socid failed, cannot open %s, because %s[%d].", "/etc/mtab", strerror(errno), errno);
        return str_serial_id;
    }
    char line[256] = {0};
    while (fgets(line, sizeof(line), fp) != NULL)  {
        char *save = NULL;
        char *disk = strtok_r(line, " ", &save);
        if (disk == NULL || strcmp(disk, "rootfs") == 0) {
            continue;
        }
        char *root = strtok_r(NULL, " ", &save);
        if (root == NULL) {
            continue;
        }
        if (strcmp(root, "/") == 0)  {
            for (char *p = disk + strlen(disk) - 1; isdigit(*p); p --) {
                *p = '\0';
            }
            int fd = open(disk, O_RDONLY);
            if (fd < 0) {
                LOG_ERROR("get hard disk socid use file[%] failed.", "/etc/mtab");
                fd = open ("/dev/sda", O_RDONLY);
            }
            if (fd < 0) {
                LOG_ERROR("get hard disk socid use file[%] failed.", "/dev/sda");
                str_serial_id = GetHardDiskSNWithUDEV(disk);
                if (!str_serial_id.empty()) {
                    str_serial_id.erase(0, str_serial_id.find_last_of("_") + 1);
                    LOG_INFO("get hard disk serial number with udev[%s].", str_serial_id.c_str());
                    str_serial_id = string_utils::Trim(str_serial_id);
                }
            } else {
                struct hd_driveid hid;
                if (ioctl(fd, HDIO_GET_IDENTITY, &hid) < 0) {
                    LOG_ERROR("get hard disk socid failed, use ioctl error, because: %s[%d].", strerror(errno), errno);
                    str_serial_id = GetHardDiskSNWithUDEV(disk);
                    if (!str_serial_id.empty()) {
                        str_serial_id.erase(0, str_serial_id.find_last_of("_") + 1);
                        LOG_INFO("get hard disk serial number with udev[%s].", str_serial_id.c_str());
                        str_serial_id = string_utils::Trim(str_serial_id);
                    }
                } else {
                    for (int i = strlen((char*)hid.serial_no) - 1; i >= 0; i--) {
                        if (!isalnum(hid.serial_no[i])) {
                            LOG_INFO("erase the last hid.serial_no character, is [%d].", hid.serial_no[i]);
                            hid.serial_no[i] = 0;
                        } else {
                            break;
                        }
                    }
                    str_serial_id = std::string((char*)hid.serial_no, strlen((char*)hid.serial_no));
                    LOG_INFO("get hard disk serial number[%s].", str_serial_id.c_str());
                    str_serial_id = string_utils::Trim(str_serial_id);
                }
                if (fd != -1) close (fd);
            }
            break;
        }
    }
    if (NULL != fp) fclose(fp);
    if (!str_serial_id.empty()) {
        return md5sum::md5(str_serial_id);
    }
    return str_serial_id;
}

std::string pc_soc_id::get_hardware_info() {
    //std::string str_hard_disk = FormatHardwareInfo();
    std::string str_hard_disk = "";
    if (!str_hard_disk.empty()) {
        return md5sum::md5(str_hard_disk);
    }
    return GetHardDiskSerialNumber();
}
