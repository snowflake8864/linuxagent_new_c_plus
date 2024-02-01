#include "dir_info.h"
#include <sys/stat.h>
#include <pwd.h>
#include "common/md5sum.h"
#include "common/utils/string_utils.hpp"
#include "common/utils/file_utils.h"


/* 
struct DIR_INFO {
    std::string file_path;
    std::string power_default;
    std::string user;
    std::string group;
    int nSize;
    long nCreateTime;
    long nModifyTime;
    std::string secPower;
    std::string strWriteType;
    std::string md5;
    std::string power;
    //可写包含可以写入新文件## 可写入文件类型 如果目录可写， 同时可以配置写入允许文件类型
    std::string str_can_write_new_file;
};

struct stat {
    mode_t   st_mode;    //文件对应的模式，文件，目录等
    ino_t   st_ino;    //inode节点号
    dev_t   st_dev;    //设备号码
    dev_t   st_rdev;    //特殊设备号码
    nlink_t  st_nlink;   //文件的连接数
    uid_t   st_uid;    //文件所有者
    gid_t   st_gid;    //文件所有者对应的组
    off_t   st_size;    //普通文件，对应的文件字节数
    time_t   st_atime;   //文件最后被访问的时间
    time_t   st_mtime;   //文件内容最后被修改的时间
    time_t   st_ctime;   //文件状态改变时间
    blksize_t st_blksize;  //文件内容对应的块大小
    blkcnt_t  st_blocks;   //伟建内容对应的块数量
   };
*/


int DirInfo::get_dir_info(const std::string &str_dir, std::vector<FILE_INFO>& dirInfo) {
    return 0;
}

std::string DirInfo::get_user_name(const uid_t &uid) {

    std::string str_user = "";
    struct passwd *pwd = getpwuid(uid);
    if (pwd && pwd->pw_name) {
        str_user = pwd->pw_name;
    } else {
        str_user = "";
    }
    return str_user;
}

void DirInfo::mode_to_letter(int mode,char *str)
{
  /*-------这个函数用来把模式值转化为字符串------*/
  str[0]='-'; /*------这里的S_*****都是宏定义，用来判断模式属性-*/
  if(S_ISDIR(mode)) str[0]='d';/*-文件夹-*/
  if(S_ISCHR(mode)) str[0]='c';/*-字符设备-*/
  if(S_ISBLK(mode)) str[0]='b';/*-块设备-*/
  if(mode & S_IRUSR) str[1]='r';/*--用户的三个属性-*/
  else str[1]='-';
  if(mode & S_IWUSR) str[2]='w';
  else str[2]='-';
  if(mode & S_IXUSR) str[3]='x';
  else str[3]='-';
  if(mode & S_IRGRP) str[4]='r';/*--组的三个属性-*/
  else str[4]='-';
  if(mode & S_IWGRP) str[5]='w';
  else str[5]='-';
  if(mode & S_IXGRP) str[6]='x';
  else str[6]='-';
  if(mode & S_IROTH) str[7]='r';/*-其他人的三个属性-*/
  else str[7]='-';
  if(mode & S_IWOTH) str[8]='w';
  else str[8]='-';
  if(mode & S_IXOTH) str[9]='x';
  else str[9]='-';
  str[10]='\0';
}

int DirInfo::get_file_info(const std::string &str_file, FILE_INFO &file_info) {

   struct stat buf_file;
    char buff[100] = {0};
    int rc = 0;
    file_info.dir = str_file;
    if (file_utils::IsSymLink(str_file)) {
        printf("is link file:%s\n", str_file.c_str());
    }
    rc = stat(str_file.c_str(), &buf_file);
    memset(buff, 0, 100);
    mode_to_letter(buf_file.st_mode, buff);
    file_info.rw = buff;
    file_info.user = get_user_name(buf_file.st_uid);
    file_info.group = get_user_name(buf_file.st_gid);
    memset(buff, 0, 100);
    if (buf_file.st_size <0) {
       buf_file.st_size = 0; 
    } else {
        sprintf(buff,"%d",(int)buf_file.st_size);
    }
    file_info.size = buff;
    memset(buff, 0, 100);
    sprintf(buff,"%d",(int)buf_file.st_ctim.tv_sec);
    file_info.starttime = buff;
    memset(buff, 0, 100);
    sprintf(buff,"%d",(int)buf_file.st_mtim.tv_sec);
    file_info.updatetime = buff;
    file_info.level = "RW";

    std::string::size_type pos = 0;
    pos = str_file.find_last_of(".");
    if (pos != std::string::npos) {
        file_info.dirtype = str_file.substr(pos + 1,str_file.length());
    } else {
        file_info.dirtype = "*unknow";
    }
    //file_info.dirtype = "php|jpeg|gif";
    if (S_ISDIR(buf_file.st_mode)) {
        file_info.type = 1;
    } else {
        file_info.type = 2;
    }
    file_info.hash =  md5sum::md5file(str_file.c_str());
    return 0;
}
