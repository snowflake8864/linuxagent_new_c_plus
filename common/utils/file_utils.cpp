#include "utils/file_utils.h"
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <list>
#include <fstream>
#include <cstring>
#include "utils/time_utils.hpp"

namespace file_utils {
std::string GetFileName(const std::string &file_path) {
    if (file_path.empty()) {
        return std::string();
    }
    std::string::size_type last_slash_pos = file_path.rfind('/');
    if (last_slash_pos == file_path.length() - 1 ||
        last_slash_pos == std::string::npos) {
        return std::string();
    }
    std::string file_name = file_path.substr(last_slash_pos + 1);
    return file_name;
}

std::string GetBaseName(const std::string &file_path) {
    std::string file_name = GetFileName(file_path);
    if (file_name.empty()) {
        return std::string();
    }
    std::string::size_type first_dot_pos = file_name.find('.');
    return file_name.substr(0, first_dot_pos);
}

std::string GetParentDir(const std::string& file_path) {
    if (file_path.empty()) {
        return std::string();
    }

    std::string trimed_path = file_path;
    string_utils::TrimRight(trimed_path, "/");
    if (file_path.empty()) {
        return std::string("/");
    }

    std::string::size_type last_slash_pos = trimed_path.rfind('/');
    if (last_slash_pos == std::string::npos) {
        return std::string();
    }
    std::string parent_dir = trimed_path.substr(0, last_slash_pos);
    return string_utils::TrimRight(parent_dir);
}

bool FollowLink(const std::string &link, std::string &real) {
    char *resolved = realpath(link.c_str(), NULL);
    if (resolved == NULL) {
        return false;
    }
    real = std::string(resolved);
    free(resolved);
    return true;
}

bool IsFile(const std::string &file_path, FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return false;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return IsFile(real_path);
            } else {
                return false;
            }
        } else {
            return true;
        }
    }
    if (S_ISREG(lsb.st_mode)) {
        return true;
    } else {
        return false;
    }
}

bool IsDir(const std::string &file_path, FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return false;
    }

    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return IsDir(real_path);
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    if (S_ISDIR(lsb.st_mode)) {
        return true;
    } else {
        return false;
    }
}

bool IsSymLink(const std::string &file_path, bool must_effective) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return false;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (must_effective) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return true;
            } else {
                return false;
            }
        } else {
            return true;
        }
    }
    return false;
}

bool IsExist(const std::string &file_path, FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return false;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return true;
            } else {
                return false;
            }
        } else {
            return true;
        }
    }
    return true;
}

int64_t GetFileSize(const std::string &file_path,
                    FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return -1;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return GetFileSize(real_path);
            } else {
                return -1;
            }
        } else {
            return lsb.st_size;
        }
    }
    if (S_ISREG(lsb.st_mode)) {
        return lsb.st_size;
    }
    return -1;
}

bool MakeDirs(const std::string& dir, const mode_t mode) {
    if (dir.empty()) {
        return false;
    }

    std::list<std::string> lst;
    lst.push_back(dir);

    while (!lst.empty()) {
        std::string dir = lst.back();
        if (IsExist(dir)) {
            lst.pop_back();
        } else {
            std::string parent_dir = GetParentDir(dir);
            if (IsExist(parent_dir) || parent_dir.empty()) {
                if (::mkdir(dir.c_str(), mode) == -1) {
                    if (errno != EEXIST) {
                        return false;
                    }
                }
                lst.pop_back();
            } else {
                lst.push_back(parent_dir);
            }
        }
    }
    return true;
}

bool IsReadable(const std::string &file_path) {
    return access(file_path.c_str(), R_OK) == 0;
}

bool IsWritable(const std::string &file_path) {
    return access(file_path.c_str(), W_OK) == 0;
}

bool IsExecuteble(const std::string& file_path) {
    return access(file_path.c_str(), X_OK) == 0;
}

uid_t GetOwnerId(const std::string &file_path,
                 FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return -1;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return GetOwnerId(real_path);
            } else {
                return (uid_t) -2;
            }
        } else {
            return lsb.st_uid;
        }
    }
    return lsb.st_uid;
}

std::string GetOwner(const std::string &file_path,
                     FOLLOW_LINK_TYPE follow_link_type) {
    std::string name;
    uid_t uid = GetOwnerId(file_path, follow_link_type);
    if (uid == static_cast<uid_t>(-2)) return name;

    struct passwd pd;
    struct passwd *result;

    char *buffer;
    size_t buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    buffer = new (std::nothrow) char[buffer_size];
    if (buffer == NULL) {
        return name;
    }
    if (getpwuid_r(uid, &pd, buffer, buffer_size, &result) == 0) {
        name = std::string(pd.pw_name);
    }
    delete[] buffer;
    return name;
}

time_t LastModified(const std::string &file_path,
                    FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return -1;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return LastModified(real_path);
            } else {
                return -2;
            }
        } else {
            return lsb.st_mtime;
        }
    }
    return lsb.st_mtime;
}

std::string FileTimeToStr(time_t time) {
    return time_utils::FormatTimeStr(time, "%Y-%m-%d %H:%M:%S");
}

std::string LastModifiedStr(const std::string& file_path,
                            FOLLOW_LINK_TYPE follow_link_type) {
    time_t last_modified = LastModified(file_path, follow_link_type);
    if (last_modified == -2) {
        return std::string();
    }
    return FileTimeToStr(last_modified);
}

long GetActiveFileNumber() {
    long open_file_counter = 0;
    char buf[256] = {0};
    FILE *fp = fopen("/proc/sys/fs/file-nr", "r");
    if (fp == NULL) {
        return 0;
    }

    if (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
        sscanf(buf, "%ld", &open_file_counter);
    }
    fclose(fp);

    return open_file_counter;
}

bool CopyFile(const std::string& from, const std::string& to) {
    std::string to_parent_dir = GetParentDir(to);
    if (!to_parent_dir.empty() && !IsDir(to_parent_dir)) {
        if (!MakeDirs(to_parent_dir)) {
            return false;
        }
    }
    std::ifstream in;
    in.open(from.c_str());
    if (!in) return false;
    std::ofstream out;
    out.open(to.c_str());
    if (!out) return false;
    out << in.rdbuf();
    in.close();
    out.close();
    return true;
}

bool MoveFile(const std::string& from, const std::string& to) {
    std::string to_parent_dir = GetParentDir(to);
    if (!to_parent_dir.empty() && !IsDir(to_parent_dir)) {
        if (!MakeDirs(to_parent_dir)) {
            return false;
        }
    }
    if (0 != rename(from.c_str(), to.c_str())) return false;
    return true;
}

bool RemoveDirs(const std::string& dir, FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(dir.c_str(), &lsb) != 0) {
        return true;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(dir, real_path);
            if (ok) {
                return RemoveDirs(real_path);
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else if (S_ISDIR(lsb.st_mode)) {
        DIR* dirp = opendir(dir.c_str());
        if (!dirp) {
           return false;
        }
        struct dirent *p_dirent;
        while((p_dirent = readdir(dirp)) != NULL) {
            if(strcmp(p_dirent->d_name, ".") == 0 || strcmp(p_dirent->d_name, "..") == 0) {
                continue;
            }
            struct stat st;
            std::string sub_path = dir + '/' + p_dirent->d_name;
            if (lstat(sub_path.c_str(), &st) == -1) {
                continue;
            }
            if (S_ISDIR(st.st_mode)) {
                if (RemoveDirs(sub_path) == false) {
                    closedir(dirp);
                    return false;
                }
            } else if (S_ISREG(st.st_mode)) {
                RemoveFile(sub_path);
            } else {
                continue;
            }
        }
        if (rmdir(dir.c_str()) == -1) {
            closedir(dirp);
            return false;
        }
        closedir(dirp);
    }
    return true;
}

namespace {
bool DoRemoveFile(const std::string& file_path) {
    if (0 != remove(file_path.c_str())) return false;
    return true;
}
}

bool RemoveFile(const std::string& file_path,
                FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return true;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return RemoveFile(real_path);
            } else {
                return false;
            }
        } else {
            return DoRemoveFile(file_path);
        }
    } else if (S_ISREG(lsb.st_mode)) {
        return DoRemoveFile(file_path);
    }
    return false;
}

FileContentSmartPtr GetFileContent(const std::string& file_path, size_t& size,
                                   FOLLOW_LINK_TYPE follow_link_type) {
    struct stat lsb;
    size = 0;
    FileContentSmartPtr null_ptr =
        FileContentSmartPtr(static_cast<void*>(NULL));
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return null_ptr;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return GetFileContent(real_path, size);
            } else {
                return null_ptr;
            }
        } else {
            return null_ptr;
        }
    } else if (S_ISREG(lsb.st_mode)) {
        int fd = open(file_path.c_str(), O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
            return null_ptr;
        }
        void* content_buf = malloc(lsb.st_size);
        if (content_buf == NULL) {
            return null_ptr;
        }
        FileContentSmartPtr ptr(content_buf, free);
        ssize_t read_size = read(fd, content_buf, lsb.st_size);
        if (read_size != lsb.st_size) {
            return null_ptr;
        }
        size = read_size;
        return ptr;
    }
    return null_ptr;
}

bool GetFileContent(const std::string& file_path, int64_t file_size, char* buf,
                    FOLLOW_LINK_TYPE follow_link_type) {
    if (file_path.empty() || file_size <= 0 || buf == NULL) return false;
    struct stat lsb;
    if (lstat(file_path.c_str(), &lsb) != 0) {
        return false;
    }
    if (S_ISLNK(lsb.st_mode)) {
        if (follow_link_type == FOLLOW_LINK) {
            std::string real_path;
            bool ok = FollowLink(file_path, real_path);
            if (ok) {
                return GetFileContent(real_path, file_size, buf);
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else if (S_ISREG(lsb.st_mode)) {
        int fd = open(file_path.c_str(), O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
            return false;
        }
        bool ret = true;
        long offset = 0;
        long remainningSize = file_size;
        while (offset < file_size) {
            static const size_t nMaxSizePerRound = 2 << 20;  // 2M
            size_t nSize2Read = (remainningSize >= (long)nMaxSizePerRound)
                                    ? nMaxSizePerRound
                                    : remainningSize;
            size_t nSizeRead = ::read(fd, buf + offset, nSize2Read);
            if (nSizeRead != nSize2Read) {
                ret = false;
                break;
            }
            remainningSize -= nSizeRead;
            offset += nSizeRead;
        }
        close(fd);
        return ret;
    }
    return false;
}

int GetPathMaxSize(const std::string &path) {
    int path_max;
#ifdef PATH_MAX
    (void)path;
    path_max = PATH_MAX;
#else
    path_max = pathconf(path, _PC_PATH_MAX);
    if (path_max <= 0)
        path_max = 4096;
#endif

    return path_max;
}
}
