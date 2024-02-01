#ifndef NET_STATE_H
#define NET_STATE_H

#include <string>
#include <map>
#include <vector>
#include "common/qh_thread/locker.hpp"
#include "osec_common/global_message.h"
#include "osec_backend/backend_mgr.h"
#include "common/log/log.h"

typedef PORT_BUSINESS_LIST NET_STATE_T;
#include <ctime>

class CPortInfo 
{
public:
    static CPortInfo *getInstance();
    CPortInfo() {
//        cycles_per_minute = BACKEND_MGR->cycles_per_minute;
        last_access_clock = 0;
        timeout_minutes = 2;
        first_update = true;
    }
    ~CPortInfo() {

    }

    static void getportinfo(std::vector<PORT_BUSINESS_LIST> &vecPort);
    bool getNetstatinfo(void); 
    bool getNetstatinfoImme(void);
    PORT_BUSINESS_LIST *GetBusinessInfoByPort(int port);

    std::map<int, PORT_BUSINESS_LIST > netstat_map;
    std::map<std::string, PORT_BUSINESS_LIST > netstat_web_map;
private:
    QH_THREAD::CMutex netstat_map_locker_;
    uint64_t last_access_clock;
    //clock_t cycles_per_minute ;
    uint64_t timeout_minutes;
    bool first_update;
    bool ShouldUpdate(void) {
        if (first_update) {
            first_update = false;
            return true;
        }
        uint64_t now = BACKEND_MGR->minutes_count;
        uint64_t elapsed_minutes = now - last_access_clock ;
        return elapsed_minutes >= timeout_minutes;
    }
    
    void updateNetstatInfo(void);
    void updateDnatInfo(void);
    void updateDockerInfo(void);
    static CPortInfo *m_pInstance;

};

#define CPORTINFO CPortInfo::getInstance()


#endif //NET_STATE_H
