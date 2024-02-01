#include "pid_file.h"
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "utils/file_utils.h"
#include "utils/string_utils.hpp"

namespace pid_file {

bool write_pid_file(const char* file_name) {
    if (file_name == NULL) {
        return false;
    }

    int fd = open(file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1) {
        return false;
    }

    // get pid
    pid_t pid = getpid();
    std::string szpid;
    std::stringstream ss;
    ss << pid;
    ss >> szpid;

    // write pid
    if (::write(fd, szpid.c_str(), szpid.size()) == -1) {
        close(fd);
        return false;
    }

    if (fd != -1) {
        close(fd);
    }

    return true;
}

bool delete_pid_file(const char* file_name) {
    return file_utils::RemoveFile(file_name);
}

bool read_pid_file(const char* file_name, std::string& pid) {
    char buffer[32] = {0};
    int fd = open(file_name, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        return false;
    }
    size_t read_size = ::read(fd, buffer, sizeof(buffer));
    pid = std::string(buffer, read_size);
    pid = string_utils::Trim(pid);

    if (fd != -1) {
        close(fd);
    }

    return true;
}

} // namespace
