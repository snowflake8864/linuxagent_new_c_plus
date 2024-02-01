#ifndef __PROCESS_MD5_MGR_H__
#define __PROCESS_MD5_MGR_H__
#include <iostream>
#include <string>
//#include <unordered_map>
#include <map>
#include <ctime>
//#include <chrono>
#include <unistd.h>
#include "common/log/log.h"
#include "common/kernel/gnHead.h"
#include "backend_mgr.h"
#include "common/qh_thread/locker.hpp"
class ProcessMd5Mgr {
    public:
        static ProcessMd5Mgr *getInstance();
        ProcessMd5Mgr() {
            timeout_minutes = 4;
            first_update = true;
        }

        void UpdateProcessMd5(const std::string& path, std::string& md5); 
    private:
        //std::unordered_map<std::string, std::pair<std::string, clock_t>> path_md5_map;
        std::map<std::string, std::pair<std::string, uint64_t> > path_md5_map;
        QH_THREAD::CMutex md5_map_locker_;
        uint64_t timeout_minutes;
        bool first_update;
        bool ShouldUpdateMd5(uint64_t last_access_clock) {
            if (first_update) {
                first_update = false;
                return true;
            }
            uint64_t now = BACKEND_MGR->minutes_count;
            uint64_t elapsed_minutes = now - last_access_clock ;
            return elapsed_minutes >= timeout_minutes;
        }

        std::string CalculateMD5(const std::string& path); 
        static ProcessMd5Mgr *m_pInstance;
};

#define PROCMD5_MGR ProcessMd5Mgr::getInstance()

#endif
