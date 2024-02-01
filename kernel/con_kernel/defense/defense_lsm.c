#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h> //fo SEND_SIG_FORCED
#endif

#include "gnHead.h"
#include "utils/utils.h"
#include "lsm/khf_commlsm.h"
#include "core/khf_core.h"
#include "defense_inner.h"
#include "defense_lsm.h"

static u_long defense_lsm_on = 0;

static int may_modify_path(const int action, struct path* path)
{
    int rc = 0;
    int is_dir = 0;
    unsigned len = 0;
    char* pathname = NULL;
    struct inode* inode = NULL;

    if(!path || !path->mnt || !path->dentry) 
    {
        return rc;    
    }

    //是否为已删除的路径
    if(d_unlinked(path->dentry)) {
        return rc;
    }

    //inode在某些情况下可能为空，
    //比如defense_hook_lsm_path_mknod调用的第二个参数dentry
    inode = path->dentry->d_inode;
    if(!inode) { return rc; }

    //是否需要放过
    if(need_defense_skip(current)) {
        return rc;
    }

    pathname = khf_get_pathname(path,&len);
    if(IS_ERR(pathname)) { return rc; }

    is_dir = S_ISDIR(inode->i_mode);
    rc = may_defense_modify(action, pathname,len,is_dir);
    khf_put_pathname(pathname);

    return rc;
}

static int may_modify_path2(const struct path* dir,
                struct dentry* dentry)
{
    struct path path = {
            .mnt = dir->mnt,
            .dentry = dentry
        };

    return may_modify_path(FILE_MODIFY, &path);
}

static int may_modify_path3(struct path *path, int is_dir)
{
    int rc = 0;
    unsigned len = 0;
    char* pathname = NULL;

    if(!path || !path->mnt || !path->dentry) 
    {
        return rc;    
    }

    //是否为已删除的路径
    if(d_unlinked(path->dentry)) {
        return rc;
    }

    //是否需要放过
    if(need_defense_skip(current)) {
        return rc;
    }

    pathname = khf_get_pathname(path,&len);
    if(IS_ERR(pathname)) { return rc; }

    rc = may_defense_modify(FILE_MODIFY, pathname,len,is_dir);
    khf_put_pathname(pathname);

    return rc;

}

//for: chattr
//it's just for chattr
static int is_set_ioctl_cmd(unsigned int cmd)
{
	return ((cmd == FS_IOC32_SETFLAGS) ||
			(cmd == FS_IOC_SETFLAGS));
}

static int may_file_ioctl(struct file *file, unsigned int cmd)
{
    int rc = 0;
    unsigned len = 0;
    char* pathname = NULL;

    if(!is_set_ioctl_cmd(cmd)) {
        goto out;
    }

    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        goto out;
    }

    pathname = khf_filp_pathname(file,&len);
    if(IS_ERR(pathname)) {
        goto out;
    }
    
    rc = may_defense_modify(FILE_MODIFY, pathname,len,0);
out:
    if(!KHF_IS_ERR_OR_NULL(pathname)) {
        khf_put_pathname(pathname);
    }
    return rc;
}

static int is_file_write(struct file* filp)
{
    int rc = 0;
    unsigned int f_flags = 0;

    if(!filp) { return rc; }

    f_flags = filp->f_flags;

    return is_modify_open_flag(f_flags);
}

static int may_file_open(struct file* file)
{
    int rc = 0;
    unsigned len = 0;
    char* pathname = NULL;

    if(!is_file_write(file)) {
        return rc;
    }

    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        return rc;
    }

    pathname = khf_filp_pathname(file,&len);
    if(IS_ERR(pathname)) {
        goto out;
    }
    
    rc = may_defense_modify(FILE_OPEN, pathname,len,0);
out:
    if(!KHF_IS_ERR_OR_NULL(pathname)) {
        khf_put_pathname(pathname);
    }

    return rc;
}

int defense_hook_lsm_ptrace_access_check(struct task_struct *child,
					            unsigned int mode)
{
	int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

	//目前只需要支持4.4以上版本的内核
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	if(mode & PTRACE_MODE_ATTACH) { 
		rc = may_defense_task_ptrace(child);
	}
#endif
    khf_self_module_put();

	return rc;
}

int defense_hook_lsm_path_unlink(const struct path *dir,
                        struct dentry *dentry)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path2(dir,dentry);

    khf_self_module_put();
    return rc;
}

int defense_hook_lsm_path_mkdir(const struct path *dir,
                        struct dentry *dentry,
                        umode_t mode)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_CREATE, (struct path*)dir);

    khf_self_module_put();
    return rc;
}

int defense_hook_lsm_path_rmdir(const struct path *dir,
                    struct dentry *dentry)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path2((struct path*)dir,dentry);
    khf_self_module_put();

    return rc;
}

//for: defense create new file
int defense_hook_lsm_path_mknod(const struct path *dir,
                    struct dentry *dentry,
                    umode_t mode, unsigned int dev)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_CREATE,(struct path*)dir);
    khf_self_module_put();

    return rc;
}

int defense_hook_lsm_path_truncate(const struct path *path)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_MODIFY,(struct path*)path);
    khf_self_module_put();

    return rc;
}

int defense_hook_lsm_path_symlink(const struct path *dir,
                struct dentry *dentry,
                const char *old_name)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_CREATE, (struct path*)dir);
    khf_self_module_put();

    return rc;
}

//for hard-link
int defense_hook_lsm_path_link(struct dentry *old_dentry,
                const struct path *new_dir,
                struct dentry *new_dentry)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    struct path path1 = { .mnt = new_dir->mnt, .dentry = old_dentry };

    if(!gotmod) { return rc; }

    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        goto out;
    }

    rc = may_modify_path(FILE_CREATE, (struct path*)new_dir);
    if(rc) { goto out; }

    rc = may_modify_path(FILE_OPEN, &path1);

out:
    khf_self_module_put();

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
int defense_hook_lsm_path_rename(const struct path *old_dir,struct dentry *old_dentry,
            const struct path *new_dir,struct dentry *new_dentry, unsigned int flags)
#else
int defense_hook_lsm_path_rename(const struct path *old_dir,struct dentry *old_dentry,
            const struct path *new_dir,struct dentry *new_dentry)
#endif
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    struct path path1 = { .mnt = old_dir->mnt, .dentry = old_dentry };

    if(!gotmod) { return rc; }

    //先判断一下是否要放过，能快一些就快一些
    //因为下面获取路径是相对较慢的
    if(need_defense_skip(current)) {
        goto out;
    }

    //先检测目地路径,此处没有必要使用new_dentry了
    //只检测目地路径目录即可
    rc = may_modify_path(FILE_CREATE, (struct path*)new_dir);
    if(rc) { goto out; }

    //再检测源路径
    rc = may_modify_path(FILE_OPEN,&path1);

out:
    khf_self_module_put();

    return rc;
}

int defense_hook_lsm_path_chmod(const struct path *path, umode_t mode)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_MODIFY,(struct path*)path);
    khf_self_module_put();
    
    return rc;
}

int defense_hook_lsm_path_chown(const struct path *path,kuid_t uid, kgid_t gid)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_modify_path(FILE_MODIFY,(struct path*)path);
    khf_self_module_put();

    return rc;
}

//for: inode
int defense_hook_lsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    if (!dir) { goto out; }

    rc = khf_dentry_path(dentry, &path);
    if (0 != rc) {
        rc = 0;                                       
        goto out; 
    } 

    is_dir = S_ISDIR(dir->i_mode);
   
    rc = may_modify_path3(&path,is_dir);
    khf_path_put(&path);
out:  
    khf_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_mkdir(struct inode *dir, struct dentry *dentry,
                            umode_t mode)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    if (!dir) {goto out; }

    rc = khf_dentry_path(dentry, &path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);

    rc = may_modify_path3(&path,is_dir);
    khf_path_put(&path);
out:    
    khf_self_module_put();
    return rc;
}


int defense_hook_lsm_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    if (!dir) {goto out; }

    rc = khf_dentry_path(dentry, &path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);

    rc = may_modify_path(FILE_MODIFY,&path);
    khf_path_put(&path);
out:   
    khf_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                                struct inode *new_dir, struct dentry *new_dentry)
{
    int rc = 0;
    int is_dir = 0;
    struct path old_path;
    struct path new_path;

    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }
     
    if(!old_dir) { goto out; } 
    //尽量快一点
    if(need_defense_skip(current)) {
        goto out;
    }

    rc = khf_dentry_path(old_dentry, &old_path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    rc = khf_dentry_path(new_dentry, &new_path);
    if (0 != rc) {
        rc = 0;
        khf_path_put(&old_path);
        goto out;
    }

    is_dir = S_ISDIR(old_dir->i_mode);
    //先检测目地路径
    rc = may_modify_path3(&new_path,is_dir);
    if(rc) { 
        khf_path_put(&old_path);
        khf_path_put(&new_path);
        goto out; 
    }

    //再检测源路径
    rc = may_modify_path3(&old_path,is_dir);

    khf_path_put(&old_path);
    khf_path_put(&new_path);

out:
    khf_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_link(struct dentry *old_dentry, struct inode *dir,
                            struct dentry *new_dentry)
{
    int rc = 0 ;
    int is_dir = 0;
    struct path old_path;
    struct path new_path;

    int gotmod = khf_try_self_module_get();
    if (!gotmod) {
        return rc;
    }

    if(!dir) {goto out; } 
    //尽量快一点
    if(need_defense_skip(current)) {
        goto out;
    }

    rc = khf_dentry_path(old_dentry,&old_path);
    if(0 != rc) {
        rc = 0;
        goto out;
    }

    rc = khf_dentry_path(new_dentry,&new_path);
    if(0 != rc) {
        rc = 0;
        khf_path_put(&old_path);
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);
    //先检测目的路径
    rc = may_modify_path3(&new_path,is_dir);
    if(rc) { 
        khf_path_put(&old_path);
        khf_path_put(&new_path);
        goto out; 
    }

     //再检测源路径
    rc = may_modify_path3(&old_path,is_dir);

    khf_path_put(&old_path);
    khf_path_put(&new_path);
out:
    khf_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_mknod(struct inode *dir, struct dentry *dentry,
                            umode_t mode, dev_t dev)
{   
    int rc = 0;
    int is_dir = 0;
    struct path path;

    int gotmod = khf_try_self_module_get();
    if(!gotmod) {
        return rc;
    }

    if(!dir) {goto out; }

    rc = khf_dentry_path(dentry,&path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);

    rc = may_modify_path3(&path,is_dir);
    khf_path_put(&path);

out:
    khf_self_module_put();
    return rc;
}

int defense_hook_lsm_inode_symlink(struct inode *dir, struct dentry *dentry,
                            const char *old_name)
{
    int rc = 0;
    int is_dir = 0;
    struct path path;
    int gotmod = khf_try_self_module_get();
    if (!gotmod) {
        return rc;
    }

    if(!dir) {goto out; }

    rc = khf_dentry_path(dentry,&path);
    if (0 != rc) {
        rc = 0;
        goto out;
    }

    is_dir = S_ISDIR(dir->i_mode);
    
    rc = may_modify_path3(&path,is_dir);
    khf_path_put(&path);

out:
    khf_self_module_put();
    return rc;
}

//for: chattr
int defense_hook_lsm_file_ioctl(struct file *file, unsigned int cmd,
            unsigned long arg)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_file_ioctl(file,cmd);
    khf_self_module_put();

    return rc;
}

//for: just for utimes,we don't care chmod,chown or others at here
int defense_hook_lsm_inode_setattr(struct dentry* dentry,struct iattr* attr)
{
    int rc = 0;
    struct path pwd;
    struct path path;
    unsigned ia_valid = ATTR_CTIME | ATTR_MTIME | ATTR_ATIME;

    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    if(!dentry || !attr) {
        goto out;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,9)
    //明确是utimes操作
    if(!(attr->ia_valid & ATTR_TOUCH)) {
        goto out;
    }
#endif

    if(!(attr->ia_valid & ia_valid)) {
        goto out;
    }

    if(d_unlinked(dentry)) {
        goto out;
    }

    //这个不是很准确：
    //dentry对应的mnt不一定跟当前进程相同
    //我们也只能保证尽可能的准确
    khf_get_fs_pwd(current->fs,&pwd);
    path.mnt = pwd.mnt;
    path.dentry = dentry;

    rc = may_modify_path(FILE_MODIFY,&path);

    khf_path_put(&pwd);

out:
    khf_self_module_put();
    return rc;
}

//for: open exist file to write,
//无法防不存时的create file
int defense_hook_lsm_file_open(struct file *file)
{
    int rc = 0;
    int gotmod = khf_try_self_module_get();
    if(!gotmod) { return rc; }

    rc = may_file_open(file);
    khf_self_module_put();

    return rc;
}

static struct khf_security_operations defense_options = {
    .name = "defense_security",

    .ptrace_access_check = defense_hook_lsm_ptrace_access_check,
#ifdef CONFIG_SECURITY_PATH
    .path_unlink = defense_hook_lsm_path_unlink,
    .path_mkdir = defense_hook_lsm_path_mkdir,
    .path_rmdir = defense_hook_lsm_path_rmdir,
    .path_mknod = defense_hook_lsm_path_mknod,
    .path_truncate = defense_hook_lsm_path_truncate,
    .path_symlink = defense_hook_lsm_path_symlink,
    .path_link = defense_hook_lsm_path_link,
    .path_rename = defense_hook_lsm_path_rename,
    .path_chmod = defense_hook_lsm_path_chmod,
    .path_chown = defense_hook_lsm_path_chown,
#else
    .inode_unlink = defense_hook_lsm_inode_unlink,
    .inode_mkdir = defense_hook_lsm_inode_mkdir,
    .inode_rmdir = defense_hook_lsm_inode_rmdir,
    .inode_rename = defense_hook_lsm_inode_rename,
    .inode_link = defense_hook_lsm_inode_link,
    .inode_mknod = defense_hook_lsm_inode_mknod,
    .inode_symlink = defense_hook_lsm_inode_symlink,
#endif
    .inode_setattr = defense_hook_lsm_inode_setattr,
    .file_ioctl = defense_hook_lsm_file_ioctl,
    .file_open = defense_hook_lsm_file_open,
};

extern int _hook_lsm_on;
void defense_hook_lsm_ops(void)
{
    if(_hook_lsm_on && !test_and_set_bit(0, &defense_lsm_on)) {
        khf_register_commlsm_hook(&defense_options);
    }
}

void defense_cleanup_lsm_ops(void)
{
}

int defense_lsm_init(void)
{
    return 0;
}

void defense_lsm_uninit(void)
{
    if(_hook_lsm_on && test_and_clear_bit(0, &defense_lsm_on)) {
        khf_unregister_commlsm_hook(&defense_options);
    }
}
