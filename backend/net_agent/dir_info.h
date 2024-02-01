#ifndef DIR_INFO
#define DIR_INFO

#include <string>
#include <unistd.h>
#include <vector>
#include "osec_common/global_message.h"


class DirInfo{

public:
    static int get_dir_info(const std::string &str_dir, std::vector<FILE_INFO>& dirInfo);
    static int get_file_info(const std::string &str_file, FILE_INFO &file_info);
    static std::string get_user_name(const uid_t &uid);
    static void mode_to_letter(int mode,char *str);
};


#endif
