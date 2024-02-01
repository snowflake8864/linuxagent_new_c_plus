#ifndef _UDISK_MONITOR_MGR_H_
#define _UDISK_MONITOR_MGR_H_

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <map>
#include <string>
#include <vector>
#include <utility>
#include "libudev.h"
#include "common/qh_thread/thread.h"
#include "osec_common/global_message.h"

class CUdiskMonitorMgr : public QH_THREAD::CThread {
  public:
    CUdiskMonitorMgr() 
      : m_pUdev_(NULL)
      , m_pUdevMonitor_(NULL)
      , m_fd_ep_(-1)
      , m_fd_udev_(-1) {
        memset(&m_ep_udev_, 0, sizeof(struct epoll_event));
    }

    ~CUdiskMonitorMgr() {
    }
  public:
    bool init();
    bool uninit();
    bool isRunning();
    bool run();
    void Quit();
    bool isQuit();
    void DoSetBlack(const std::vector<USB_INFO>& vecBlack);
    void DoSetWhite(const std::vector<USB_INFO>& vecWhite);
    int get_local_all_device(std::vector<USB_INFO>& vecUsbInfo);
    void SetConf(const CONFIG_INFO &conf);
  private:
    int getDeviceEventInfo(struct udev_device *device);
    int action_stop_device(const std::string& strSerial);
    int usb_dev_stop(struct udev_device *dev);
  protected:
    virtual void* thread_function(void* param);
  private:
    struct udev *m_pUdev_;
    struct udev_monitor *m_pUdevMonitor_;
    struct epoll_event m_ep_udev_;
    int m_fd_ep_;
    int m_fd_udev_;
    QH_THREAD::CMutex m_mutex_monitor;
    std::vector<USB_INFO> m_blackUsb;
    std::vector<USB_INFO> m_WhiteUsb;
    CONFIG_INFO m_conf;
};

#endif /* MONITOR_UDISK_EVENT_MGR_H_ */
