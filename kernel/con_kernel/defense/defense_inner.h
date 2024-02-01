#ifndef DEFENSE_INNER_H
#define DEFENSE_INNER_H

#include "core/khf_core.h"

extern u_long defense_debug;
#define DEFENSE_LOG_INFO     LOG_INFO
#define DEFENSE_LOG_ERROR    LOG_ERROR

#define DEFENSE_LOG_DEBUG(fmt, args...) {  \
            if(test_bit(0,&defense_debug)) { \
                printk(KERN_DEBUG "[%s][%d]: "fmt, __FUNCTION__, __LINE__,##args); \
            } else { LOG_DEBUG(fmt,##args); } }


void defense_do_debug(int bon);

int handle_cmd_add_white_exes(void* data,int size);
int defense_policy_init(void);
void defense_policy_uninit(void);

int get_defense_white_exes(char* buf,size_t len);
int get_defense_protect_paths(char* buf,size_t len);

int is_modify_open_flag(int flags);

int need_defense_skip(struct task_struct* task);
int may_defense_task_kill(struct task_struct* task,
                    int sig,pid_t spid);
int may_defense_task_ptrace(struct task_struct* task);
int may_defense_modify(const int action, const char* kpathname,
                    size_t len,int is_dir);
void defense_task(int pid,bool enabled,bool bchild);

void cleanup_white_exes(void);
int is_current_white_exe(void);
int is_defense_white_exe(const char* exe,size_t len);

//bhold-->表是是否执行进程保护操作,如果不执行，
//则仅仅将相应进程加到受保护列表中,后续自保开关来时再进行保护
int hold_one_proc(struct task_struct* task,bool bhold);
int unhold_one_proc(struct task_struct* task);
void unhold_all_procs(void);
void hold_all_procs(void);
void cleanup_hold_procs(void);
ssize_t get_all_hold_procs(char* buf,size_t len);

int defense_exec_fake_init(void);
void defense_exec_fake_uninit(void);

int init_defense_task(void);
void uninit_defense_task(void);
int defense_tlv_proto_init(void);
void defense_tlv_proto_uninit(void);
int is_expoit_enable(void);
int is_file_enable(void);
int is_defense_enable(void);
void turn_off_defense(void);
void turn_on_defense(void);
int is_process_enable(void);
void turn_on_self(void);
void turn_off_self(void);
int is_self_enable(void);
int is_syslog_enable(void);
int is_file_need_wait(void);
int is_process_need_wait(void);
int is_expoit_need_wait(void);
int is_file_protect_need_wait(void);
int is_syslog_inner_enable(void);
int is_syslog_outer_enable(void);
int is_syslog_dns_enable(void);
int is_proc_enable(void);



int file_audit_filepath(const int action, pid_t pid, const char * filepath, const size_t len, int is_dir);
int file_audit_filepath_rename(const int action, pid_t pid, const char * filepath, const size_t len1, const char* filepathnew,const size_t len2,int is_dir);
int exe_audit_filepath(const char* filename);
int may_defense_modify_mv(const int action_type, const char * kpathname, const size_t len1, const char * kpathnamenew, const size_t len2,int is_dir);




#endif
