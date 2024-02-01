#ifndef UTILS_FILE_UTILS_H_
#define UTILS_FILE_UTILS_H_

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string>
#include <tr1/memory>
#include "utils/string_utils.hpp"

namespace file_utils {
enum FOLLOW_LINK_TYPE { FOLLOW_LINK, NOT_FOLLOW_LINK };
bool IsFile(const std::string& file_path,
            FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
bool IsDir(const std::string& file_path,
           FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
bool IsExist(const std::string& file_path,
             FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
bool IsSymLink(const std::string& file_path, bool must_effective = false);
bool FollowLink(const std::string& link, std::string& real);
int64_t GetFileSize(const std::string& file_path,
                    FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);

bool MakeDirs(const std::string& dir, const mode_t mode = 0755);

// GetParentDir("/") == "/"
std::string GetParentDir(const std::string& file_path);
std::string GetFileName(const std::string& file_path);
// The base name consists of all characters in the file up to (but not
// including) the first '.' character.
std::string GetBaseName(const std::string& file_path);
bool IsReadable(const std::string& file_path);
bool IsWritable(const std::string& file_path);
bool IsExecuteble(const std::string& file_path);
time_t LastModified(const std::string& file_path,
                    FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
std::string FileTimeToStr(time_t time);
std::string LastModifiedStr(
    const std::string& file_path,
    FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
uid_t GetOwnerId(const std::string& file_path,
                 FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
std::string GetOwner(const std::string& file_path,
                     FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
long GetActiveFileNumber();

bool CopyFile(const std::string& from, const std::string& to);
bool MoveFile(const std::string& from, const std::string& to);
// return false is not dir
bool RemoveDirs(const std::string& dir,
                FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
bool RemoveFile(const std::string& file_path,
                FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
using string_utils::JoinPath;
using string_utils::FormatPathSlash;

typedef std::tr1::shared_ptr<void> FileContentSmartPtr;
FileContentSmartPtr GetFileContent(
    const std::string& file_path, size_t& size,
    FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
//外部保证buf大小足够容纳file的内容
bool GetFileContent(const std::string& file_path, int64_t file_size, char* buf,
                    FOLLOW_LINK_TYPE follow_link_type = NOT_FOLLOW_LINK);
int GetPathMaxSize(const std::string &path);
}

#endif  /* UTILS_FILE_UTILS_H_ */
