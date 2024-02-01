#include <linux/types.h>
#include "utils/utils.h"
#include "gnHead.h"
#include "core/gnkernel.h"
#include "defense_inner.h"
//#include "utils/pid_path.h"
#include "dpi/rules.h"
#include "dpi/pattern_tbl.h"

static inline int get_process_path(pid_t pid, char *buf, size_t buflen) {
    struct path path_struct;
    char* real_path = NULL;
    char dbuffer[512];
    char path[128];
    dbuffer[0] = '\0';
    memset(path, 0, 128);
    snprintf(path, 128, "/proc/%d/exe", pid);
    // 解析路径

    int ret = kern_path(path, LOOKUP_FOLLOW, &path_struct);
    if (ret) {
        printk("ret=%d,path[%s]\n",ret, path);
        return -1;
    }
    // 获取绝对路径
    real_path = d_path(&path_struct, dbuffer, 512);
    if (real_path) {
        strncpy(buf, real_path, buflen);
    }
    path_put(&path_struct);
    return 0;
}



static inline int send_nl_data_to_user(const uint8_t type, const uint8_t need_wait, const int16_t rule_idx, const uint8_t protect_rw, /*const int is_file, */const int action, pid_t pid, const char * filepath, const char* filepathnew, int is_dir)
{
    int nDeny = 0;
    struct av_file_info *pi;
    pi = (struct av_file_info*)kmalloc(sizeof(struct av_file_info), GFP_KERNEL);
    if (pi) {
        memset(pi, 0, sizeof(*pi));
        pi->uid = CURRENT_UID;
        pi->pid = CURRENT_PID;
        pi->type = action;
        pi->is_dir = !!is_dir;
        //pi->is_file = (is_file == 3);
        pi->rules_type = type;
        pi->rules_idx = rule_idx;
        pi->protect_rw = protect_rw;
        strncpy(pi->path, filepath, sizeof(pi->path)-1);

        if (filepathnew != NULL) {
            strncpy(pi->dst_path, filepathnew, sizeof(pi->dst_path)-1);
        }

        get_process_path(CURRENT_PID, pi->comm, sizeof(pi->comm));
        if (need_wait) {
            pi->is_monitor_mode = 0;
            send_wait_nl_data(NL_POLICY_AV_FILE_CHANGE_NOTIFY, pi, sizeof(struct av_file_info), &pi->pwait_flag, &nDeny);
        } else {
            pi->is_monitor_mode = 1;
            send_nowait_nl_data(NL_POLICY_AV_FILE_CHANGE_NOTIFY, pi, sizeof(struct av_file_info));
        }
        LOG_INFO("file_audit_filepath filename:%s,type:%d, nDeny:%d, protect_rw:%x,is_dir:%d\n",filepath,  action, nDeny, protect_rw,is_dir);
        kfree(pi);
    }
    return nDeny;
}

static inline int send_self_protect_data_to_user(const int action, pid_t pid, const char * filepath, const char* filepathnew)
{
    int nDeny = 0;
    struct av_self_protection_info *pi = (struct av_self_protection_info*)kmalloc(sizeof(struct av_self_protection_info), GFP_KERNEL);
    if (pi) {
        memset(pi, 0, sizeof(*pi));
        pi->uid = CURRENT_UID;
        pi->pid = CURRENT_PID;
        strncpy(pi->path, filepath, sizeof(pi->path)-1);

        if (filepathnew != NULL) {
            strncpy(pi->dst_path, filepathnew, sizeof(pi->dst_path)-1);
        }

        get_process_path(CURRENT_PID, pi->comm, sizeof(pi->comm));
        switch(action) {
            case FILE_CREATE:
            {
                pi->type = 4700;
                break;
            }
            case FILE_MODIFY:
            {
                pi->type = 4702;
                break;
            }
            case FILE_RENAME:
            {
                pi->type = 4703;
                break;
            }
            case FILE_REMOTE:
            {
                pi->type = 4704;
                break;
            }
            default:
                pi->type = 4701;
                break;
        }
        send_nowait_nl_data(NL_POLICY_AV_SELF_PROTECTION_NOTIFY, pi, sizeof(struct av_self_protection_info));
        kfree(pi);
    }
    return nDeny;
}

int file_audit_filepath(const int action, pid_t pid, const char * filepath, const size_t len, int is_dir)
{
    int i;
    int retv = -1;
    if (unlikely(G_state_id_inc <= 1)) {
        return 0;
    }
    if(is_self_process()) {
        return 0;
    }

    int rules_info = 0;
    dpi_result_t result ;
    memset(&result, 0, sizeof(dpi_result_t));
    result.is_dir = is_dir;
    //LOG_INFO("file_audit_filepath  current[%s].pid:%d, action:%d, filepath:%s, is_dir[%d]\n", CURRENT_COMM, pid, action, filepath, is_dir);
    if (file_acsmSearch3(filepath, len, &result) == -1) {
        return 0;
    }
    int nDeny = 0;
    for (i = 0; i < 5 && i < result.cnt; i ++) {
        switch(result.type[i]) {
            case 3:
                if (is_self_enable()) {
                    //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                    if (action == FILE_OPEN) {
                        if (unlikely(strlen(CURRENT_COMM) == 2 && strncmp(CURRENT_COMM, "cp", 2) == 0)) {
                            send_self_protect_data_to_user(FILE_CREATE,  pid, filepath, NULL);
                            return 1;
                        }
                        //LOG_INFO("file_audit_filepath retv:%d, current[%s].pid:%d,  action:%d, filepath:%s\n",retv, CURRENT_COMM, pid, action, filepath);
                        return 0;
                    } else {
                        send_self_protect_data_to_user(action,  pid, filepath, NULL);
                        return 1;
                    }
                }
                break;
            case 2://protect
            {
                if (!is_defense_enable()) {
                    return nDeny;
                }
#if 0
                if (result.action[i] == 1) {
                    continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#else
                switch(result.action[i]) {
                    case 0:
                    case 3:
                        {
                            break;
                        }
                    case 1:
                    case 2:
                        {
                            goto break_protect;
                        }
                }

#endif
                nDeny += send_nl_data_to_user(2, is_file_protect_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath,NULL, is_dir);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s,wait=%d\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath, is_file_protect_need_wait());
              break_protect:
                break;
            }
            case 1://lesuo
            {
                if (!is_defense_enable()) {
                    return nDeny;
                }
#if 0                
                if (result.action[i] == 1) {
                    continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#endif
                nDeny += send_nl_data_to_user(1, is_expoit_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath, NULL, is_dir);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s, wait=%d\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath, is_expoit_need_wait());

                break;
            }
            case 0:
            default:
                return 0;
        }
    }

    return !!nDeny;
}

int file_audit_filepath_rename(const int action, pid_t pid, const char * filepath, const size_t len1, const char* filepathnew, const size_t len2, int is_dir)
{
    struct av_file_info *pi;
    int i = 0;
    int retv = 0;

    if (unlikely(G_state_id_inc <= 1)) {
        return 0;
    }
    if(is_self_process()) {
        return 0;
    }
    int rules_info = 0;
    dpi_result_t result;
    memset(&result, 0, sizeof(dpi_result_t));
    result.is_dir = is_dir;
    if (file_acsmSearch3(filepath, len1, &result) == -1) {
        return 0;
    }
    int nDeny = 0;
    for (i = 0; i < 5 && i < result.cnt; i ++) {
        //LOG_INFO("===result.type:%d====\n", result.type[i]); 
        switch(result.type[i]) {
            case 3:
                if (unlikely(!is_self_enable())) {
                    return nDeny;
                }
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                if (action != FILE_OPEN) {
                    send_self_protect_data_to_user(action,  pid, filepath, filepathnew);
                    return 1;
                }
                break;
            case 2://protect
                {
                    if (unlikely(!is_defense_enable())) {
                        return nDeny;
                    }
#if 0
                    if (result.action[i] == 1) {
                        continue;
                    } else if (result.action[i] == 2) {
                        return 1;
                    }
#else
                    switch(result.action[i]) {
                        case 0:
                        case 3:
                            {
                                break;
                            }
                        case 1:
                        case 2:
                            {
                                goto lesuo_continue;
                            }
                    }

#endif

                    nDeny += send_nl_data_to_user(2, is_file_protect_need_wait(), result.rule_idx[i], result.protect_rw[i], action, pid, filepath, filepathnew, is_dir);
                    //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                    result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                    goto lesuo_continue;
//continue_protect_1:
                    continue;
                }
            case 1://lesuo
            {
                if (unlikely(!is_defense_enable())) {
                    return nDeny;
                }
#if 0                
                if (result.action[i] == 1) {
                    continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#endif
                nDeny += send_nl_data_to_user(1, is_expoit_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath,filepathnew,is_dir);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                goto lesuo_continue;
            }
            case 0:
            default:
                break;
        }
lesuo_continue:
     continue;

    }

    memset(&result, 0, sizeof(dpi_result_t));
    result.is_dir = is_dir;
    if (file_acsmSearch3(filepathnew, len2, &result) == -1) {
        return 0;
    }
    //nDeny = 0;
    for (i = 0; i < 5 && i < result.cnt; i ++) {
        switch(result.type[i]) {
            case 3:
                if (unlikely(!is_self_enable())) {
                    return nDeny;
                }
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
                if (action != FILE_OPEN) {
                    send_self_protect_data_to_user(action,  pid, filepath, filepathnew);
                    return 1;
                }
                break;
            case 2://protect
            {
                if (unlikely(!is_defense_enable())) {
                    return nDeny;
                }

#if 0
                    if (result.action[i] == 1) {
                        continue;
                    } else if (result.action[i] == 2) {
                        return 1;
                    }
#else
                    switch(result.action[i]) {
                        case 0:
                        case 3:
                            {
                                break;
                            }
                        case 1:
                        case 2:
                            {
                                goto break_protect_2;
                            }
                    }

#endif


                nDeny += send_nl_data_to_user(2, is_file_protect_need_wait(), result.rule_idx[i], result.protect_rw[i], action, pid, filepath, filepathnew, is_dir);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);
break_protect_2:
                break;
            }
            case 1://lesuo
            {
                if (unlikely(!is_defense_enable())) {
                    return nDeny;
                }
#if 0                
                if (result.action[i] == 1) {
                    continue;
                } else if (result.action[i] == 2) {
                    return 1;
                }
#endif                
                nDeny += send_nl_data_to_user(1, is_expoit_need_wait(), result.rule_idx[i], result.protect_rw[i],  action, pid, filepath,filepathnew,is_dir);
                //LOG_INFO("file_audit_filepath result.cnt:%d, current[%s].pid:%d, type:%d action:%d, filepath:%s\n",\
                result.cnt, CURRENT_COMM, pid, result.type[i], action, filepath);

                break;
            }
            case 0:
            default:
                return 0;
        }
    }

out:

    return nDeny;
}


const char* filter_process_array[] = {
    "/usr/bin/sudo",
    NULL
};
int exe_audit_filepath(const char* filename)
{
    struct av_process_info *pi;
    int nDeny = 0;
    int i = 0;
    int action = 0;
    if(is_self_process()) {
        return 0;
    }

    //LOG_INFO("exe_audit_filepath current[%s]  filename:%s\n",CURRENT_COMM, filename);
    #if 1
    #if 0
    if (memcmp(CURRENT_COMM, "MagicArmor", 10) == 0) {
        LOG_INFO("exe_audit_filepath current[%s]  filename:%s\n",CURRENT_COMM, filename);
        return 0;
    }
    #endif
    while(filter_process_array[i] != NULL) {
        if(strcmp(filename, filter_process_array[i]) == 0) {
            return 0;
        }
        i++;
    }
    #else

    if ((action = process_acsmSearch(filename, strlen(filename))) != 2) {
        return action;
    }
    #endif
    //if (is_process_enable() || is_syslog_enable()) 
    {
        
        pi = (struct av_process_info*)kmalloc(sizeof(struct av_process_info), GFP_KERNEL);
        if (pi) {
            memset(pi, 0, sizeof(*pi));
            pi->uid = CURRENT_UID;
            pi->pid = CURRENT_PID;
            pi->ppid = CURRENT_PPID;
            pi->param_pos = 0;
            pi->type = 7;
            memcpy(pi->comm, CURRENT_COMM, sizeof(pi->comm));
            memcpy(pi->comm_p, CURRENT_COMM_P, sizeof(pi->comm_p));
            strncpy(pi->path, filename, sizeof(pi->path)-1);
            //get_user_command(current, pi);
            //get_process_arguments(CURRENT_PID, pi); 
            if (is_process_need_wait()) {
                pi->is_monitor_mode = 0;
                send_wait_nl_data(NL_POLICY_AV_PROCESS_EXEC_NOTIFY, pi, sizeof(struct av_process_info), &pi->pwait_flag, &nDeny);
            } else {
                pi->is_monitor_mode = 1;
                send_nowait_nl_data(NL_POLICY_AV_PROCESS_EXEC_NOTIFY, pi, sizeof(struct av_process_info));
                //LOG_INFO("file_audit_filepath_rename filename:%s,type:%d, nDeny:%d\n",filename,  action, nDeny);
            } 
            //LOG_INFO("exe_audit_filepath filename :%s, nDeny:%d,comm[%s],comm_p[%s]\n", filename, nDeny, pi->comm, pi->comm_p);
            kfree(pi);
        } else {
            LOG_INFO("no enough mem for av_process_info\n");
        }
    }
    return nDeny;
}
