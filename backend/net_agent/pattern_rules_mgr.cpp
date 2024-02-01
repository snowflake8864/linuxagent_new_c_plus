#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "common/utils/string_utils.hpp"
//#include "common/singleton.hpp"
#include "pattern_rules_mgr.h"
#include "common/kernel/gnHead.h"
#include "common/log/log.h"

#define FILE_PATTERNS_PROC_FILE "/proc/osec/dpi/file_patterns"
#define DPI_RULE_PROC_FILE "/proc/osec/dpi/rules"
static std::string GlobalTrustDirPatterns;
static std::string ExiportDirPatterns;
static std::string ConstFilePatterns;
static std::string ProtectDirPatterns;
static std::string ProtectDirWhitePatterns;
static std::string ProtectDirIncludeFileExePatterns;
static std::string ProtectDirExcludeFileExePatterns;

static std::string GlobalTrustDirRules;
static std::string ExiportDirRules;
static std::string ConstFileRules;
static std::string ProtectDirRules;
static std::string ProtectDirWhiteRules;
static std::string ProtectDirIncludeFileExeRules;
static std::string ProtectDirExcludeFileExeRules;


static int fileExists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1; // 文件存在
    }   
    return 0; // 文件不存在
}

static int echoCmd2Proc(const char *proc_file, const char *cmd, const size_t size)
{
   	int fd = open(proc_file, O_RDWR);
    if (fd < 0) {
		LOG_ERROR("open fail: %s\n", strerror(errno));  
        return -1;
    }
    LOG_INFO("=========[%s],size:%d\n",cmd,size);
    ::write(fd, cmd, size);
    close(fd);
    return 0;
}


PatternRules_MGR::PatternRules_MGR()
{
    ConstFilePatterns.clear();
    ConstFileRules.clear();
    GlobalTrustDirPatterns.clear();
    GlobalTrustDirRules.clear();
    ExiportDirPatterns.clear();
    ExiportDirRules.clear();
    ProtectDirPatterns.clear();
    ProtectDirRules.clear();
 }

PatternRules_MGR::~PatternRules_MGR()
{
    ConstFilePatterns.clear();
    GlobalTrustDirPatterns.clear();
    ExiportDirPatterns.clear();
    ProtectDirPatterns.clear();

}

enum PATTERN_ACTION {
    PASS_RETURN,
    BLOCK_RETURN,
    CONTINUE_RUN,
    SELF_PROTECTION,
    TRUSTDIR_ACTION
};

enum PATTERN_TYPE {
    SELF_PROTECTION_TYPE,
    LESOU_PROTECTION_TYPE,
    TAMPER_PROTECTION_TYPE
};
const char* filter_file_array[] = {
    "/proc/",
    "/dev/",
    "/var/log/",
    "/var/cache/",
    "/var/tmp/",
    "/var/backups/",
    "/var/lib/",
    "/run/",
    "/sys/",
    "/srv/",
    NULL
};

const char* filter_process_array[] = {
    "/usr/bin/sudo",
    NULL
};

void PatternRules_MGR::AddFilePattern(int enable)
{
    ClearFilePattern();
    ClearDpiRules();
    if (ConstFilePatterns.size() > 0) {
        ConstFilePatterns.clear();
        ConstFileRules.clear();
    }
    if (enable == 1) {
        ConstFilePatterns += "name=self_1,key=/var/lib/dpkg/info/osec.\n";
        ConstFileRules += "target=self,pattern=self_1,type=3\n";
        ConstFilePatterns += "name=self_2,key=/opt/osec,pkt_len=-1,case_offset=1\n";
        ConstFileRules += "target=self,pattern=self_2,type=3\n";
        ConstFilePatterns += "name=self_3,key=/opt/osec/,case_offset=1\n";
        ConstFileRules += "target=self,pattern=self_3,type=3\n";
        ConstFilePatterns += "name=self_4,key=/etc/systemd/system/osec.service,case_offset=1\n";
        ConstFileRules += "target=self,pattern=self_4,type=3\n";
        ConstFilePatterns += "name=self_5,key=/etc/systemd/system/multi-user.target.wants/osec.service,case_offset=1\n";
        ConstFileRules += "target=self,pattern=self_5,type=3\n";
        ConstFilePatterns += "name=self_6,key=/etc/init.d/osecservicecentos,case_offset=1\n";
        ConstFileRules += "target=self,pattern=self_6,type=3\n";
    }
    //echoCmd2Proc(FILE_PATTERNS_PROC_FILE, ConstFilePatterns.c_str(), ConstFilePatterns.size());
    //echoCmd2Proc(DPI_RULE_PROC_FILE, ConstFileRules.c_str(), ConstFileRules.size());
    //BuildFilePattern();
    setPatternRules();
}

void PatternRules_MGR::SetGlobalTrustDir(std::vector<GlobalTrusrDir> global_trustdir) 
{
//    if (global_trustdir.empty()) {
//        return;
//    }
    ClearFilePattern();
    ClearDpiRules();
    //QH_THREAD::CMutexAutoLocker lock(&m_pattern_locker_);
    if (GlobalTrustDirPatterns.size() > 0) {
        GlobalTrustDirPatterns.clear();
        GlobalTrustDirRules.clear();
    }

    int size = global_trustdir.size();
    std::vector<GlobalTrusrDir>::iterator iter;
    int i = 0; 
    char buf[32];
    char depth_str[32] = {0};
    for (iter = global_trustdir.begin(); iter!= global_trustdir.end(), i<size; iter++, i++) {
        if (i>=50) {
            LOG_INFO("trust global dir is too big and break, size:%d", size);
            break;
        }
        memset(buf, 0, 32);
        sprintf(buf, "trueDir_%d", i);
        GlobalTrustDirPatterns += "name=";
        GlobalTrustDirPatterns += buf;
        GlobalTrustDirPatterns += ",key=";
        GlobalTrustDirPatterns += iter->dir; 
        GlobalTrustDirRules += "target=TDir_rule";
        if (iter->type == 1) {
            if (iter->is_extend == 0) {
                GlobalTrustDirPatterns += ",isnot_extend=1";
            }
            sprintf(depth_str, ",depth=%d", (strlen(iter->dir.c_str())));
            GlobalTrustDirPatterns += depth_str;
        } else {
            GlobalTrustDirPatterns += ",pkt_len=-1";
        }
        GlobalTrustDirPatterns += ",case_offset=1";
        GlobalTrustDirPatterns += "\n";
        GlobalTrustDirRules += ",type=0";
        GlobalTrustDirRules += ",pattern=";
        GlobalTrustDirRules += buf;
        GlobalTrustDirRules += "\n";
    }

    setPatternRules();
}

void PatternRules_MGR::SetExiportDir(std::vector<POLICY_EXIPOR_PROTECT> &g_VecExiportInfo) 
{
//    if (g_VecExiportInfo.empty()) {
//        return;
//    }
    ClearFilePattern();
    ClearDpiRules();
    //QH_THREAD::CMutexAutoLocker lock(&m_pattern_locker_);
    if (ExiportDirPatterns.size() > 0) {
        ExiportDirPatterns.clear();
        ExiportDirRules.clear();
    }
    int size = g_VecExiportInfo.size();
    std::vector<POLICY_EXIPOR_PROTECT>::iterator iter;
    int i = 0;
    char index_str[32];
    for (iter = g_VecExiportInfo.begin(); iter!= g_VecExiportInfo.end(), i<size; iter++, i++) {
        if (i>=50) {
            LOG_INFO("exiport global dir is too big and break, size:%d", size);
            break;
        }
        memset(index_str,0, 32);
        sprintf(index_str, "exiportInfo_%d", i);
        ExiportDirPatterns += "name=";
        ExiportDirPatterns += index_str;
        ExiportDirRules += "target=";
        //ExiportDirRules += index_str;
        ExiportDirRules += "exiportInfo";
        ExiportDirRules += ",pattern=";
        ExiportDirRules += index_str;

        if (iter->type == 1) { //后缀
            ExiportDirPatterns += ",key=.";
            ExiportDirPatterns += iter->file_type; 
            memset(index_str,0, 16);
            sprintf(index_str, "-%d,", (strlen(iter->file_type.c_str()) + 1));
            ExiportDirPatterns += ",offset=";
            ExiportDirPatterns += index_str;
            //ExiportDirRules += ",is_file=1";
            ExiportDirRules += ",action=3"; //include file suffex
        } else {
            ExiportDirPatterns += ",case_offset=1";
            ExiportDirPatterns += ",key=";
            ExiportDirPatterns += iter->file_type; 
            memset(index_str,0, 32);
            sprintf(index_str, ",depth=%d", (strlen(iter->file_type.c_str())));
            ExiportDirPatterns += index_str;
        }

        ExiportDirRules += ",type=1\n";
        ExiportDirPatterns += "\n";
    }

    setPatternRules();
}

void PatternRules_MGR::ClearExiportDir(void) 
{
    ClearFilePattern();
    ClearDpiRules();
    //QH_THREAD::CMutexAutoLocker lock(&m_pattern_locker_);
    if (ExiportDirPatterns.size() > 0) {
        ExiportDirPatterns.clear();
        ExiportDirRules.clear();
    }
    setPatternRules();
}

void PatternRules_MGR::SetProtectDir(std::vector<POLICY_PROTECT_DIR> &vecProtectDir) 
{
//    if (vecProtectDir.empty()) {
//        return;
//    }
    ClearFilePattern();
    ClearDpiRules();
   
    //QH_THREAD::CMutexAutoLocker lock(&m_pattern_locker_);
    ProtectDirPatterns.clear();
    ProtectDirWhitePatterns.clear();
    ProtectDirRules.clear();
    ProtectDirWhiteRules.clear();
    ProtectDirIncludeFileExePatterns.clear();
    ProtectDirIncludeFileExeRules.clear();
    ProtectDirExcludeFileExePatterns.clear();
    ProtectDirExcludeFileExeRules.clear();
    int size = vecProtectDir.size();

    std::vector<std::string> vectemp;
    std::vector<std::string>::iterator _iter;
    std::vector<POLICY_PROTECT_DIR>::iterator iter;
    int i = 0, j = 0;
    char i_str[8];
    char j_str[8];
    char offset_str[8];
    char protect_rw_str[8];
    char depth_str[32] = {0};
    for (iter = vecProtectDir.begin(); iter != vecProtectDir.end(); iter++, i++) {
        if (i>=50) {
            LOG_INFO("exiport global dir is too big and break, size:%d", size);
            break;
        }
        memset(protect_rw_str, 0, 8);
        snprintf(protect_rw_str,8, "%d", iter->protect_rw);
        memset(i_str, 0, 8);
        snprintf(i_str,8, "%d", i);
        LOG_INFO("=====protec rules %s, protect_rw[%x]\n", i_str, iter->protect_rw);
        if(!iter->is_white.empty()) {
            vectemp.clear();
            string_utils::Split(vectemp,iter->is_white, "|");
            j = 0;
            for (_iter = vectemp.begin(); _iter != vectemp.end(); _iter++, j++) {
                memset(j_str, 0, 8);
                snprintf(j_str,8, "_%d", j);
                ProtectDirWhitePatterns += "name=protectExcludeDir_";
                ProtectDirWhitePatterns += i_str;
                ProtectDirWhitePatterns += j_str;
                ProtectDirWhitePatterns += ",key=";
                ProtectDirWhitePatterns += vectemp[j];
                ProtectDirWhitePatterns += "\n";
                //ProtectDirWhiteRules += "target=protectExcludeDir_";
                //ProtectDirWhiteRules += i_str;
                //ProtectDirWhiteRules += j_str;
                ProtectDirWhiteRules += "target=protectExcludeDir";
                ProtectDirWhiteRules += ",pattern=protectExcludeDir_";
                ProtectDirWhiteRules += i_str;
                ProtectDirWhiteRules += j_str;
                ProtectDirWhiteRules += ",type=2";
                ProtectDirWhiteRules += ",action=1"; //exclude dir
                ProtectDirWhiteRules += ",rule_idx=";
                ProtectDirWhiteRules += i_str;
                ProtectDirWhiteRules += ",level=1\n";
            }
       }
        //protect_dir[i]._type = iter->type;
        ProtectDirPatterns += "name=ProtectDir_";
        ProtectDirPatterns += i_str;
        ProtectDirPatterns += ",type=2"; //TAMPER_PROTECTION_TYPE
        ProtectDirPatterns += ",key=";
        ProtectDirPatterns += iter->dir; 
        if (iter->type == 1) { //文件夹
            if (iter->is_extend == 0) {
                ProtectDirPatterns += ",isnot_extend=1";
            }
            sprintf(depth_str, ",depth=%d", (strlen(iter->dir.c_str())));
            ProtectDirPatterns += depth_str;
            ProtectDirPatterns += ",case_offset=1";
        } else {
            ProtectDirPatterns += ",case_offset=1";
            ProtectDirPatterns += ",pkt_len=-1";
            //sprintf(depth_str, ",depth=%d", (strlen(iter->dir.c_str())));
            //ProtectDirPatterns += depth_str;
        }
        ProtectDirPatterns += "\n";
       
        if(!iter->include_file.empty()) {
            vectemp.clear();
            string_utils::Split(vectemp,iter->include_file, "|");
            j = 0;
            for (_iter = vectemp.begin(); _iter != vectemp.end(); _iter++, j++) {
                memset(j_str, 0, 8);
                snprintf(j_str,8, "_%d", j);
                ProtectDirIncludeFileExePatterns += "name=protectIncFileExe_";
                ProtectDirIncludeFileExePatterns += i_str;
                ProtectDirIncludeFileExePatterns += j_str;
                ProtectDirIncludeFileExePatterns += ",key=.";
                ProtectDirIncludeFileExePatterns += vectemp[j];
                memset(offset_str,0, 8);
                sprintf(offset_str, "-%d", (strlen(vectemp[j].c_str()) + 1));
                ProtectDirIncludeFileExePatterns += ",offset=";
                ProtectDirIncludeFileExePatterns += offset_str;
                //ProtectDirIncludeFileExePatterns += ",is_file=1";
                ProtectDirIncludeFileExePatterns += "\n";
                //ProtectDirWhiteRules += "target=protectExcludeDir_";
                //ProtectDirWhiteRules += i_str;
                //ProtectDirWhiteRules += j_str;
                ProtectDirIncludeFileExeRules += "target=protectIncFileExe_";
                ProtectDirIncludeFileExeRules += i_str;
                ProtectDirIncludeFileExeRules +=  ",pattern=ProtectDir_";
                ProtectDirIncludeFileExeRules += i_str;
                ProtectDirIncludeFileExeRules +=  ">protectIncFileExe_";
                ProtectDirIncludeFileExeRules += i_str;
                ProtectDirIncludeFileExeRules += j_str;
                ProtectDirIncludeFileExeRules += ",rule_idx=";
                ProtectDirIncludeFileExeRules += i_str;
                ProtectDirIncludeFileExeRules += ",action=3"; //include file suffex
                ProtectDirIncludeFileExeRules += ",protect_rw=";
                ProtectDirIncludeFileExeRules += protect_rw_str;
//				ProtectDirIncludeFileExeRules += ",is_file=1";
                ProtectDirIncludeFileExeRules += ",type=2\n";
            }

        } else if(!iter->file_ext.empty()) {

            ProtectDirRules +=  "target=ProtectDir_";
            ProtectDirRules += i_str;
            ProtectDirRules +=  ",pattern=ProtectDir_";
            ProtectDirRules += i_str;
            ProtectDirRules += ",rule_idx=";
            ProtectDirRules += i_str;
            ProtectDirRules += ",protect_rw=";
            ProtectDirRules += protect_rw_str;
            ProtectDirRules += ",type=2\n";


            vectemp.clear();
            string_utils::Split(vectemp,iter->file_ext, "|");
            j = 0;
            for (_iter = vectemp.begin(); _iter != vectemp.end(); _iter++, j++) {
                memset(j_str, 0, 8);
                snprintf(j_str,8, "_%d", j);
                ProtectDirExcludeFileExePatterns += "name=protectExcFileExe_";
                ProtectDirExcludeFileExePatterns += i_str;
                ProtectDirExcludeFileExePatterns += j_str;
                ProtectDirExcludeFileExePatterns += ",key=.";
                ProtectDirExcludeFileExePatterns += vectemp[j];
                ProtectDirExcludeFileExePatterns += ",pkt_len=-1";
                memset(offset_str,0, 8);
                sprintf(offset_str, "-%d", (strlen(vectemp[j].c_str()) + 1));
                ProtectDirExcludeFileExePatterns += ",offset=";
                ProtectDirExcludeFileExePatterns += offset_str;
//                ProtectDirExcludeFileExePatterns += ",is_file=1";
                ProtectDirExcludeFileExePatterns += "\n";
                ProtectDirExcludeFileExeRules += "target=protectExcFileExe";
                ProtectDirExcludeFileExeRules +=  ",pattern=ProtectDir_";
                ProtectDirExcludeFileExeRules += i_str;
                ProtectDirExcludeFileExeRules +=  ">protectExcFileExe_";
                ProtectDirExcludeFileExeRules += i_str;
                ProtectDirExcludeFileExeRules += j_str;
                ProtectDirExcludeFileExeRules += ",rule_idx=";
                ProtectDirExcludeFileExeRules += i_str;
                //ProtectDirExcludeFileExeRules += ",action=1";
                ProtectDirExcludeFileExeRules += ",action=2"; //file exe include
                ProtectDirExcludeFileExeRules += ",level=1";
//				ProtectDirExcludeFileExeRules += ",is_file=1";
                ProtectDirExcludeFileExeRules += ",type=2\n";
            }

        } else {
            //ProtectDirRules +=  "target=ProtectDir_";
            //ProtectDirRules += i_str;
            ProtectDirRules +=  "target=ProtectDir_";
            ProtectDirRules += i_str;
            ProtectDirRules +=  ",pattern=ProtectDir_";
            ProtectDirRules += i_str;
            ProtectDirRules += ",rule_idx=";
            ProtectDirRules += i_str;
            ProtectDirRules += ",protect_rw=";
            ProtectDirRules += protect_rw_str;
            ProtectDirRules += ",type=2\n";
        }
    }
    setPatternRules();
}

void PatternRules_MGR::ClearProtectDir(void) 
{
    ClearFilePattern();
    ClearDpiRules();

    ProtectDirPatterns.clear();
    ProtectDirWhitePatterns.clear();
    ProtectDirRules.clear();
    ProtectDirWhiteRules.clear();
    ProtectDirIncludeFileExePatterns.clear();
    ProtectDirIncludeFileExeRules.clear();
    ProtectDirExcludeFileExePatterns.clear();
    ProtectDirExcludeFileExeRules.clear();
    setPatternRules();
}


void PatternRules_MGR::ClearFilePattern(void)
{
	int fd = open(FILE_PATTERNS_PROC_FILE, O_RDWR);
    if (fd < 0) {
		LOG_ERROR("open fail: %s\n", strerror(errno));  
        return;
    }

    ::write(fd, "c\n", 2);
    close(fd);
}
void PatternRules_MGR::ClearDpiRules(void)
{
	int fd = open(DPI_RULE_PROC_FILE, O_RDWR);
    if (fd < 0) {
		LOG_ERROR("open fail: %s\n", strerror(errno));  
        return;
    }

    ::write(fd, "c\n", 2);
    close(fd);
}

void PatternRules_MGR::BuildFilePattern(void)
{
	int fd = open(FILE_PATTERNS_PROC_FILE, O_RDWR);
    if (fd < 0) {
		LOG_ERROR("open fail: %s\n", strerror(errno));  
        return;
    }

    ::write(fd, "b\n", 2);
    close(fd);
}


void PatternRules_MGR::load_pattern_rules(void)
{
    if (ConstFilePatterns.size() > 0) {
        echoCmd2Proc(FILE_PATTERNS_PROC_FILE, ConstFilePatterns.c_str(), ConstFilePatterns.size());
        echoCmd2Proc(DPI_RULE_PROC_FILE, ConstFileRules.c_str(), ConstFileRules.size());
    }
    if (GlobalTrustDirPatterns.size() > 0) {
        echoCmd2Proc(FILE_PATTERNS_PROC_FILE, GlobalTrustDirPatterns.c_str(),GlobalTrustDirPatterns.size());
        echoCmd2Proc(DPI_RULE_PROC_FILE, GlobalTrustDirRules.c_str(), GlobalTrustDirRules.size());
    }
    if (ExiportDirPatterns.size() > 0) {
        echoCmd2Proc(FILE_PATTERNS_PROC_FILE, ExiportDirPatterns.c_str(),ExiportDirPatterns.size());
        echoCmd2Proc(DPI_RULE_PROC_FILE, ExiportDirRules.c_str(), ExiportDirRules.size());
    }
    if (ProtectDirPatterns.size() > 0) {
        echoCmd2Proc(FILE_PATTERNS_PROC_FILE, ProtectDirPatterns.c_str(), ProtectDirPatterns.size());
    }
    if (ProtectDirRules.size() > 0) {
        echoCmd2Proc(DPI_RULE_PROC_FILE, ProtectDirRules.c_str(), ProtectDirRules.size());
        LOG_INFO("================protect rule [%s]\n", ProtectDirRules.c_str());
    }

    if (ProtectDirWhitePatterns.size() > 0) {
        echoCmd2Proc(FILE_PATTERNS_PROC_FILE, ProtectDirWhitePatterns.c_str(), ProtectDirWhitePatterns.size());
        echoCmd2Proc(DPI_RULE_PROC_FILE, ProtectDirWhiteRules.c_str(), ProtectDirWhiteRules.size());
    }
    if (ProtectDirIncludeFileExePatterns.size() > 0) {
        echoCmd2Proc(FILE_PATTERNS_PROC_FILE, ProtectDirIncludeFileExePatterns.c_str(), ProtectDirIncludeFileExePatterns.size());
        echoCmd2Proc(DPI_RULE_PROC_FILE, ProtectDirIncludeFileExeRules.c_str(), ProtectDirIncludeFileExeRules.size());
    } 
    if (ProtectDirExcludeFileExePatterns.size() > 0) {
        echoCmd2Proc(FILE_PATTERNS_PROC_FILE, ProtectDirExcludeFileExePatterns.c_str(), ProtectDirExcludeFileExePatterns.size());
        echoCmd2Proc(DPI_RULE_PROC_FILE, ProtectDirExcludeFileExeRules.c_str(), ProtectDirExcludeFileExeRules.size());
    }
    BuildFilePattern();
}

bool PatternRules_MGR::Init() {
    if (m_inited_ == true) {
        LOG_INFO("the CThreadProcess mgr has been inited before.");
        return true;
    }
    loadPatternRulesFlag = 0;
    //AddFilePattern();
    m_inited_ = true;
    QH_THREAD::CMultiThread::SetConcurrentSize(1);
    QH_THREAD::CMultiThread::Run();
    return true;
}

void PatternRules_MGR::UnInit() {
    if (QH_THREAD::CMultiThread::IsRunning()) {
        QH_THREAD::CMultiThread::SynStop();
    }
    QH_THREAD::CMultiThread::Release();
}

void* PatternRules_MGR::thread_function(void* param) {
    while(!QH_THREAD::CMultiThread::IsCancelled()) {
        sleep(5);
        QH_THREAD::CMutexAutoLocker lock(&m_cache_locker_);
        if (loadPatternRulesFlag > 0) {
            load_pattern_rules();
        }
        loadPatternRulesFlag = 0;
    }
    return NULL;
}

int PatternRules_MGR::setPatternRules(void) {
    QH_THREAD::CMutexAutoLocker lock(&m_cache_locker_);
    loadPatternRulesFlag = 1;
    return 0;
}
