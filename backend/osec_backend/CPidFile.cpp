#include "CPidFile.h"
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "common/utils/file_utils.h"
#include "common/log/log.h"

int CPidFile::write_pid_file(const char* file_name) {
    int ret = -1;
    if (file_name == NULL) return ret;
    int fd = open(file_name, O_RDWR | O_CREAT,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1) return ret;
    //file_utils::SetFDCLOEXEC(fd);
    if (flock(fd, LOCK_NB | LOCK_EX) == -1) {
        close(fd);
        return ret;
    }
    //清空原先内容
    if (::ftruncate(fd, 0) == -1) {
        return ret;
    }
    //设置偏移
    lseek(fd, 0, SEEK_SET);
    // get pid
    pid_t pid = getpid();
    std::string szpid;
    std::stringstream ss;
    ss << pid;
    ss >> szpid;
    // write pid
    if (::write(fd, szpid.c_str(), szpid.size()) == -1) {
        return ret;
    }
    close(fd);
    return fd;
}

bool CPidFile::delete_pid_file(const char* file_name) {
    if (file_name == NULL) return false;

    if (!file_utils::IsFile(file_name)) return false;

    return remove(file_name) != 0 ? false : true;
}
