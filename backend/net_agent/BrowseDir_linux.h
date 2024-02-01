#ifndef _BROWSEDIR_LINUX_H_
#define _BROWSEDIR_LINUX_H_

#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <vector>

#ifndef _MAX_PATH
#define _MAX_PATH 260
#endif

class CBrowseDirLinux
{
public:
    //缺省构造器
    static bool BrowseDir(const char *dir );
    static std::vector<std::string> GetDirFilenames(const char *dir, bool bRecursion);

};

#endif  //_BROWSEDIR_LINUX_H_
