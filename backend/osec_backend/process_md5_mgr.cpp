#include "process_md5_mgr.h"
#include "common/md5sum.h"
ProcessMd5Mgr *ProcessMd5Mgr::m_pInstance = NULL;
void ProcessMd5Mgr::UpdateProcessMd5(const std::string& path, std::string& md5) {
    QH_THREAD::CMutexManualLocker lck(&md5_map_locker_);
    lck.lock();
    std::map<std::string, std::pair<std::string, uint64_t> >::iterator it = path_md5_map.find(path);
    if (it == path_md5_map.end() || ShouldUpdateMd5(it->second.second)) {
        lck.unlock();
        md5 = CalculateMD5(path); // Calculate MD5 here
        lck.lock();
        path_md5_map[path] = { md5, BACKEND_MGR->minutes_count };
    } else {
        md5 = it->second.first;
    }
    lck.unlock();
}

ProcessMd5Mgr *ProcessMd5Mgr::getInstance()
{
    if (m_pInstance == NULL) {
        m_pInstance = new ProcessMd5Mgr();
    }
    return m_pInstance;
}

std::string ProcessMd5Mgr::CalculateMD5(const std::string& path) {
    return md5sum::md5file(path.c_str());
}

