#include "udisk_monitor_mgr.h"
#include "common/log/log.h"
#include "common/utils/file_utils.h"
#include "common/singleton.hpp"
#include <linux/fs.h> 
#include "libudev.h"
#include "../ent_client_net_agent.h"
#include "common/md5sum.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
bool CUdiskMonitorMgr::init() {
    
    if (m_pUdev_ == NULL) {
        m_pUdev_ = udev_new ();
        if (m_pUdev_ == NULL) {
            LOG_ERROR_DEV("CUdiskEventMgr init, UdevNew failed.");
            return false;
        }
        if (m_pUdevMonitor_ == NULL) {
            m_pUdevMonitor_ = udev_monitor_new_from_netlink(m_pUdev_, "udev");
            if (m_pUdevMonitor_ == NULL) {
                LOG_ERROR_DEV("CUdiskEventMgr init, UdevNew monitor failed.");
                return false;
            }
        }
    }
    m_fd_udev_ = udev_monitor_get_fd(m_pUdevMonitor_);
    if (udev_monitor_filter_add_match_subsystem_devtype (m_pUdevMonitor_, "block", NULL)<0){
        LOG_ERROR_DEV("CUdiskEventMgr init, Udev set block filter failed(block).");
        return false;
    }
    if (udev_monitor_filter_add_match_subsystem_devtype (m_pUdevMonitor_, "usb", NULL)<0){
        LOG_ERROR_DEV("CUdiskEventMgr init, Udev set usb filter failed(block).");
        return false;
    }

    if (udev_monitor_enable_receiving(m_pUdevMonitor_) < 0) {
        LOG_ERROR_DEV("CUdiskEventMgr init, Udev bind failed.");
        return false;
    }

    if (m_fd_ep_ < 0) {
#ifdef EPOLL_CLOEXEC
        m_fd_ep_ = epoll_create1(EPOLL_CLOEXEC);
        if (m_fd_ep_ < 0) {
            LOG_ERROR_DEV("CUdiskEventMgr init, Udev epoll create failed.");
            return false;
        }
#else
        // Since Linux 2.6.8, the size argument is ignored, but must be greater than zero
        m_fd_ep_ = epoll_create(32);
        if (m_fd_ep_ < 0) {
            LOG_ERROR_DEV("CUdiskEventMgr init, Udev epoll create failed.");
            return false;
        }
        file_utils::SetFDCLOEXEC(m_fd_ep_);
#endif
    }
    m_ep_udev_.events = EPOLLIN;
    m_ep_udev_.data.fd = m_fd_udev_;
    if (epoll_ctl(m_fd_ep_, EPOLL_CTL_ADD, m_fd_udev_, &m_ep_udev_) < 0) {
        LOG_ERROR_DEV("CUdiskEventMgr init, Udev failed to fd add epoll.");
        return false;
    }
    LOG_INFO("CUdiskMonitorMgr monitor sucess");
    return true;
}

bool CUdiskMonitorMgr::uninit() {
    QH_THREAD::CThread::quit();
    QH_THREAD::CThread::join();
    if (m_fd_ep_ >= 0) {
        close(m_fd_ep_);
        m_fd_ep_ = -1;
    }
    if (NULL != m_pUdevMonitor_) {
        udev_monitor_unref(m_pUdevMonitor_);
        m_pUdevMonitor_ = NULL;
    }
    if (NULL != m_pUdev_) {
        udev_unref(m_pUdev_);
        m_pUdev_ = NULL;
    }
    memset(&m_ep_udev_, 0, sizeof(struct epoll_event));
    return true;
}
 
bool CUdiskMonitorMgr::isRunning() {
    return (QH_THREAD::CThread::isRunning());
}

bool  CUdiskMonitorMgr::isQuit() {
    return (QH_THREAD::CThread::isQuit());
}

bool CUdiskMonitorMgr::run() {
    int ret = QH_THREAD::CThread::run(NULL);
    if (ret != 0) {
        LOG_ERROR_DEV("CUdiskMonitorMgr run, start thread error.");
        return false;
    }
   
    LOG_INFO("start control thread success");
    return true;
}

void CUdiskMonitorMgr::Quit(){
    LOG_INFO("CUdiskMonitorMgr Quit");
    QH_THREAD::CThread::quit();
}

void *CUdiskMonitorMgr::thread_function(void *param) {
    while (!isQuit()) {
        struct epoll_event ev[8];
        memset(&ev, 0, sizeof(ev)); 
        int fdcount = epoll_wait(m_fd_ep_, ev, ARRAY_SIZE(ev), 100);
        for (int i = 0; i < fdcount; i++) {
            if (ev[i].data.fd == m_fd_udev_ && ev[i].events & EPOLLIN) {
                struct udev_device *device = udev_monitor_receive_device(m_pUdevMonitor_);
                if (device == NULL) {
                    LOG_ERROR_DEV("CUdiskEventMgr thread fun, no device from socket.");
                    continue;
                }
                if (m_conf.usb_switch) {
                    getDeviceEventInfo(device);
                }
                udev_device_unref(device);
            }
        }
    }
    LOG_INFO("step out of the dev control thread");
    return NULL;
}

int CUdiskMonitorMgr::getDeviceEventInfo(struct udev_device *device) {
#if 0
    if (m_conf.usb_switch == 0) {
        LOG_INFO("usb policy switch disable");
        return 0;
    }
#endif
    std::string str_path = "";
    std::string str_deviceId = "";
    struct udev_list_entry *list_entry;
    const char *str = udev_device_get_action(device);
    if (str == NULL) {
        LOG_ERROR_DEV("CUdiskEventMgr getting device event info, Unable to obtain udev device action.");
        return -1;
    }
    const char *udev_type = udev_device_get_devtype(device);
    const char *id_bus = udev_device_get_property_value(device, "ID_BUS");
    if (( NULL == udev_type) || (id_bus == NULL)) {
        return -1;;
    }

    if ( (0 != strcmp(udev_type, "disk")) || (strcmp("usb", id_bus) != 0)) {
        return -1;
    }
    std::string vid;
    std::string pid;
    std::string eid;
    std::string usb_name;
    udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device)) {
        const char *pKeyName = udev_list_entry_get_name(list_entry);
        const char *pKeyValue = udev_list_entry_get_value(list_entry);
        if (strcmp("ID_SERIAL_SHORT" ,pKeyName) == 0) {
            if (strlen(pKeyValue)>=60) {
                std::string sno = pKeyValue;
                str_deviceId = sno.substr(0, 59);
            } else {
                str_deviceId = pKeyValue;
            }
        } else if (strcmp("ID_MODEL_ID" ,pKeyName) == 0) {
            pid = pKeyValue;
        }  else if (strcmp("ID_VENDOR_ID" ,pKeyName) == 0) {
            vid = pKeyValue;
        }  else if (strcmp("ID_VENDOR" ,pKeyName) == 0) {
            usb_name = pKeyValue;
        }  
    }
    if ( (pid.empty()) || (vid.empty())) {
        return 1;
    }

    eid = str_deviceId + "_" + pid + "_" + vid;
    if (eid.length() <= 3) {
        return 1;
    }

    std::vector<LOG_INFO> vecloginfo;
    LOG_INFO info;
    info.nTime = time(NULL);
    info.peripheral_name = usb_name;
    info.peripheral_remark = usb_name;
    info.nLevel = 1;
    info.peripheral_eid = md5sum::md5(eid);
    if (memcmp(str, "add", 3) == 0) {
        LOG_DEBUG("monitor add str_path: %s, str_deviceId:%s", str_path.c_str(), str_deviceId.c_str());
        std::vector<USB_INFO> vecUsbInfo;
        get_local_all_device(vecUsbInfo);
        Singleton<CEntClientNetAgent>::Instance().UploadUsbInfo(vecUsbInfo);
        std::vector<USB_INFO>::iterator iter;
        for (iter = m_blackUsb.begin(); iter != m_blackUsb.end(); iter++) {
            if (iter->eid == info.peripheral_eid) {
                if (m_conf.usb_protect) {
                    usb_dev_stop(device);
                    info.nType = 9006;
                    info.nLevel = 3;
                } else {
                    info.nType = 9004;
                    info.nLevel = 3;
                }
                vecloginfo.push_back(info);
                Singleton<CEntClientNetAgent>::Instance().UoloadUsbLog(vecloginfo);
                return 1;
            }
        }

        for (iter = m_WhiteUsb.begin(); iter != m_WhiteUsb.end(); iter++) {
            if (iter->eid == info.peripheral_eid) {
                return 1;
            }
        }
        if (m_conf.usb_protect) {
            info.nType = 9005;
            info.nLevel = 2;
            usb_dev_stop(device);
        } else {
             info.nType = 9003;
             info.nLevel = 2;
        }
        vecloginfo.push_back(info);
        Singleton<CEntClientNetAgent>::Instance().UoloadUsbLog(vecloginfo);
        return 1;
    } else if (memcmp(str, "remove", 6) == 0) {
        LOG_DEBUG("monitor remove str_path: %s, str_deviceId:%s", str_path.c_str(), str_deviceId.c_str());
        std::vector<USB_INFO> vecUsbInfo;
        get_local_all_device(vecUsbInfo);
        Singleton<CEntClientNetAgent>::Instance().UploadUsbInfo(vecUsbInfo);

        std::vector<USB_INFO>::iterator iter;
        for (iter = m_blackUsb.begin(); iter != m_blackUsb.end(); iter++) {
            if (iter->eid == info.peripheral_eid) {
                info.nType = 9007;
                 info.nLevel = 3;
                vecloginfo.push_back(info);
                Singleton<CEntClientNetAgent>::Instance().UoloadUsbLog(vecloginfo);
                return 1;
            }
        }

        for (iter = m_WhiteUsb.begin(); iter != m_WhiteUsb.end(); iter++) {
            if (iter->eid == info.peripheral_eid) {
                return 1;
            }
        }
        if (m_conf.usb_protect) {
            info.nType = 9008;
            info.nLevel = 2;
        } else {
            info.nType = 9008;
            info.nLevel = 2;
        }
        vecloginfo.push_back(info);
        Singleton<CEntClientNetAgent>::Instance().UoloadUsbLog(vecloginfo);
        return 1;
    }
    return -1;
}

#ifdef LOW_VERSION_UDEV
static int echoAuthorized(const char *sysfs_path)
{

        FILE* file = fopen(sysfs_path, "w");
        if (!file) {
                LOG_ERROR("Failed to open sysfs file: %s\n", sysfs_path);
                return -1;
        }

        const char* value = "0";
        ssize_t bytes_written = fwrite(value, sizeof(char), strlen(value), file);
        fclose(file);

        if (bytes_written == -1) {
                LOG_ERROR("Failed to write to sysfs file.\n");
                return -1;
        }

        return 0;
}

int CUdiskMonitorMgr::usb_dev_stop( struct udev_device *dev)
{
    char sysfs_path[256] = {0};
    const char* syspath = NULL;
    if (udev_device_get_sysattr_value(dev, "authorized") != NULL) {
        LOG_DEBUG("Detecting USB equipment");
        syspath = udev_device_get_syspath(dev);
        snprintf(sysfs_path, sizeof(sysfs_path), "/%s/authorized", syspath);
        if (echoAuthorized(sysfs_path) == -1) {
                return -1;
        }
        if (NULL != udev_device_get_devtype(dev)) {
            struct udev_device *pdev = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_device");
            if (!pdev) {
                LOG_ERROR("Unable to find parent usb device.");
                return -1;
            }
            syspath = udev_device_get_syspath(pdev);
            snprintf(sysfs_path, sizeof(sysfs_path), "/%s/authorized", syspath);
            if (echoAuthorized(sysfs_path) == -1) {
                    return -1;
            }
        }
    }
    else {
        dev = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_device");
        if (!dev) {
            LOG_ERROR("Unable to find parent usb device.");
            return -1;
        }
        if (udev_device_get_sysattr_value(dev, "authorized") != NULL) {
            syspath = udev_device_get_syspath(dev);
            snprintf(sysfs_path, sizeof(sysfs_path), "/%s/authorized", syspath);
            if (echoAuthorized(sysfs_path) == -1) {
                    return -1;
            }
        } else {
            LOG_ERROR("Can not found attr authorized parent");
            return -1;
        }
    }

    return 0;
}
#else
int CUdiskMonitorMgr::usb_dev_stop(struct udev_device *dev) {
    if (udev_device_get_sysattr_value(dev, "authorized") != NULL) {
        LOG_DEBUG("Detecting USB equipment");
        udev_device_set_sysattr_value(dev, "authorized", (char *)"0");
        if (NULL != udev_device_get_devtype(dev)) {
            LOG_DEBUG("Find parent, set authorized")
            struct udev_device *pdev = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_device");
            if (!pdev) {
                LOG_ERROR("Unable to find parent usb device.");
                return -1;
            }
            udev_device_set_sysattr_value(pdev, "authorized", (char *)"0");
        }
    }
    else {
        dev = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_device");
        if (!dev) {
            LOG_ERROR("Unable to find parent usb device.");
            return -1;
        }
        if (udev_device_get_sysattr_value(dev, "authorized") != NULL) {
            LOG_DEBUG("Detecting USB equipment");
            udev_device_set_sysattr_value(dev, "authorized", (char *)"0");
        } else {
            LOG_ERROR("Can not found attr authorized parent");
            return -1;
        }
    }
    return 0;
}
#endif

int CUdiskMonitorMgr::get_local_all_device(std::vector<USB_INFO>& vecUsbInfo) {
    int rc = -1;
    struct udev *p_udev_ = udev_new ();
    if (p_udev_ == NULL) {
        LOG_ERROR("GetDeviceList p_udev_ null");
        return -1;
    }
    struct udev_enumerate *pEnumerate = udev_enumerate_new(p_udev_);
    if (pEnumerate == NULL) {
        LOG_ERROR("GetDeviceList udev_enumerate_new error: %s[%d].", strerror(errno), errno);
        return -1;
    }
    udev_enumerate_add_match_subsystem(pEnumerate, "block");
    udev_enumerate_add_match_subsystem(pEnumerate, "usb");
    udev_enumerate_scan_devices(pEnumerate);
    struct udev_list_entry *devices, *dev_list_entry;
    devices = udev_enumerate_get_list_entry(pEnumerate);

    udev_list_entry_foreach(dev_list_entry, devices) {
        std::string strSerial_in;
        struct udev_list_entry *list_entry;
        const char *path = udev_list_entry_get_name(dev_list_entry);
        struct udev_device *dev = udev_device_new_from_syspath(p_udev_, path);
        const char *udev_type = udev_device_get_devtype(dev);
        
        if (NULL == udev_type) {
            udev_device_unref(dev);
            continue;
        }
        if (0 != strcmp(udev_type, "disk")) {
            udev_device_unref(dev);
            continue;
        }
        USB_INFO info;
        std::string pid;
        std::string vid;
        std::string major_id;
        std::string disk_type;
        bool flag = true;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev)) {
            const char *pKeyName = udev_list_entry_get_name(list_entry);
            const char *pKeyValue = udev_list_entry_get_value(list_entry);
            if (strcmp("ID_SERIAL_SHORT" ,pKeyName) == 0) {
                if (strlen(pKeyValue)>=60) {
                    std::string sno = pKeyValue;
                    strSerial_in = sno.substr(0, 59);
                } else {
                    strSerial_in = pKeyValue;
                }
            } else if (strcmp("ID_VENDOR" ,pKeyName) == 0) {
                info.name = pKeyValue;
            } else if (strcmp("ID_MODEL_ID" ,pKeyName) == 0) {
                pid = pKeyValue;
            }  else if (strcmp("ID_VENDOR_ID" ,pKeyName) == 0) {
                vid = pKeyValue;
            } else if (strcmp("MAJOR", pKeyName) == 0) {
                major_id = pKeyValue;
                if (major_id != "8") {
                    flag = false;
                    break;
                }
            } else if (strcmp("DEVTYPE", pKeyName) == 0) {
                disk_type = pKeyValue;
                if (disk_type != "disk") {
                    flag = false;
                    break;
                }
            }
        }
        info.eid = strSerial_in + "_" + pid + "_" + vid;
        info.intro = info.name;
        info.type = "usb大容量";
        info.eid = md5sum::md5(info.eid);
        if ((info.eid.length() > 3) && (flag == true)) {
            std::vector<USB_INFO>::iterator iter;
            for (iter = vecUsbInfo.begin(); iter != vecUsbInfo.end(); iter++) {
                if (iter->eid == info.eid) {
                    flag = false;
                    break;
                }
            }
            if (flag == true) {
                vecUsbInfo.push_back(info);
            }
        }
        udev_device_unref(dev);
    }

    if (NULL != pEnumerate) {
        udev_enumerate_unref(pEnumerate);
        pEnumerate = NULL;
    }
    if (NULL != p_udev_) {
        udev_unref(p_udev_);
        p_udev_ = NULL;
    }
    return rc;
}

int CUdiskMonitorMgr::action_stop_device(const std::string& strSerial) {
    int rc = -1;
    struct udev *p_udev_ = udev_new ();
    if (p_udev_ == NULL) {
        LOG_ERROR("GetDeviceList p_udev_ null");
        return -1;
    }
    struct udev_enumerate *pEnumerate = udev_enumerate_new(p_udev_);
    if (pEnumerate == NULL) {
        LOG_ERROR("GetDeviceList udev_enumerate_new error: %s[%d].", strerror(errno), errno);
        return -1;
    }
    udev_enumerate_add_match_subsystem(pEnumerate, "block");
    udev_enumerate_add_match_subsystem(pEnumerate, "usb");
    udev_enumerate_scan_devices(pEnumerate);
    struct udev_list_entry *devices, *dev_list_entry;
    devices = udev_enumerate_get_list_entry(pEnumerate);

    udev_list_entry_foreach(dev_list_entry, devices) {
        std::string strSerial_in;
        struct udev_list_entry *list_entry;
        const char *path = udev_list_entry_get_name(dev_list_entry);
        struct udev_device *dev = udev_device_new_from_syspath(p_udev_, path);
        const char *udev_type = udev_device_get_devtype(dev);
        
        if (NULL == udev_type) {
            udev_device_unref(dev);
            continue;
        }
        if (0 != strcmp(udev_type, "disk")) {
            udev_device_unref(dev);
            continue;
        }
        std::string pid;
        std::string vid;
        std::string eid;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev)) {
            const char *pKeyName = udev_list_entry_get_name(list_entry);
            const char *pKeyValue = udev_list_entry_get_value(list_entry);
            if (strcmp("ID_SERIAL_SHORT" ,pKeyName) == 0) {
                if (strlen(pKeyValue)>=60) {
                    std::string sno = pKeyValue;
                    strSerial_in = sno.substr(0, 59);
                } else {
                    strSerial_in = pKeyValue;
                }
            } else if (strcmp("ID_MODEL_ID" ,pKeyName) == 0) {
                pid += pKeyValue;
            }  else if (strcmp("ID_VENDOR_ID" ,pKeyName) == 0) {
                vid += pKeyValue;
            }
        }

        eid = strSerial_in + "_" + pid + "_" + vid;
        if (eid == strSerial) {
            rc = usb_dev_stop(dev);
            udev_device_unref(dev);
            break; 
        }
        udev_device_unref(dev);
    }

    if (NULL != pEnumerate) {
        udev_enumerate_unref(pEnumerate);
        pEnumerate = NULL;
    }
    if (NULL != p_udev_) {
        udev_unref(p_udev_);
        p_udev_ = NULL;
    }
    return rc;
}

void CUdiskMonitorMgr::DoSetBlack(const std::vector<USB_INFO>& vecBlack) {
    m_blackUsb.clear();
    m_blackUsb = vecBlack;
}
void CUdiskMonitorMgr::DoSetWhite(const std::vector<USB_INFO>& vecWhite) {
    m_WhiteUsb.clear();
    m_WhiteUsb = vecWhite;
}

void CUdiskMonitorMgr::SetConf(const CONFIG_INFO &conf) {
    m_conf = conf;
}
