#include "BrowseDir_linux.h"


bool CBrowseDirLinux::BrowseDir(const char *dir)
{
    DIR* dp;
    struct dirent *entry;
    struct stat statbuf;

    if((dp = opendir(dir)) == NULL)
    {
        printf("Can't open directory %s\n", dir);
        return false;
    };

    //chdir(dir);
    while((entry = readdir(dp)) != NULL)
    {
        lstat(entry->d_name, &statbuf);

        if(S_ISDIR(statbuf.st_mode))
        {
            if(strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            std::string dir_name = dir;

            //if(dir_name.back() == '/')
            if(dir_name[dir_name.length()-1] == '/')
            {
                dir_name = dir_name + entry->d_name;
            }
            else
            {
                dir_name = dir_name + '/' + entry->d_name;
            }
            BrowseDir((char*)dir_name.c_str());
        }
        else
        {
            std::string file_name = dir;
            if(file_name[file_name.length()-1]  == '/')
            {
                file_name = file_name + entry->d_name;
            }
            else
            {
                file_name = file_name + '/' + entry->d_name;
            }

        }
    }

    //chdir("..");
    closedir(dp);
    return true;
}

std::vector<std::string> CBrowseDirLinux::GetDirFilenames(const char *dir, bool bRecursion )
{
    std::vector<std::string>filename_vector;
#if 1
    DIR* dp;
    struct dirent *entry;
    struct stat statbuf;

    if((dp = opendir(dir)) == NULL)
    {
        printf("Can't open directory %s\n", dir);
        return filename_vector;
    };

    //chdir(dir);

    while((entry = readdir(dp)) != NULL)
    {
        lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode))
        {
            if(strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            std::string dir_name = dir;

            if(dir_name[dir_name.length()-1] == '/')
            {
                dir_name = dir_name + entry->d_name;
            }
            else
            {
                dir_name = dir_name + '/' + entry->d_name;
            }
            filename_vector.push_back(dir_name);

        }
        else
        {
            std::string file_name = dir;
            if(file_name[file_name.length()-1] == '/')
            {
                file_name = file_name + entry->d_name;
            }
            else
            {
                file_name = file_name + '/' + entry->d_name;
            }
	        filename_vector.push_back(file_name);
        }
    }

    //chdir("..");

    closedir(dp);
#endif
    return filename_vector;
}


