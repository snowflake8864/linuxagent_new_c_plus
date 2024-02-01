#ifndef PATTERN_RULES_MGR_H
#define PATTERN_RULES_MGR_H

#include <string>
#include "osec_common/global_message.h"
#include "common/qh_thread/multi_thread.h"

class PatternRules_MGR:public QH_THREAD::CMultiThread {
public:
    PatternRules_MGR();
    ~PatternRules_MGR();
    void SetGlobalTrustDir(std::vector<GlobalTrusrDir> global_trustdir);
    void SetExiportDir(std::vector<POLICY_EXIPOR_PROTECT> &g_VecExiportInfo);
    void ClearExiportDir(void);
    void SetProtectDir(std::vector<POLICY_PROTECT_DIR> &vecProtectDir); 
    void ClearProtectDir(void); 
    void AddFilePattern(int enable);
    bool Init();
    void UnInit(); 
private:
    void AddConstPattern(void);
    void ClearConstPattern(void);
    void BuildFilePattern(void);
    void ClearFilePattern(void);
    void AddProcessPattern(void);
    void ClearProcessPattern(void);
    void load_pattern_rules(void);

    int setPatternRules(void);
    void ClearDpiRules(void);
    int const_pattern_fd;
    int file_pattern_fd;
    int process_pattern_fd;
  protected:
    volatile bool m_inited_;
    virtual void* thread_function(void* param);
  private:
    QH_THREAD::CMutex m_cache_locker_;
    int loadPatternRulesFlag;

};

#endif 
