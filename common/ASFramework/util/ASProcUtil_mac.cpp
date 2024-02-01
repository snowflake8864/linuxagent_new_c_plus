#include "ASProcUtil.h"
#include <mach-o/dyld.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

int CASProcUtil::GetCurPid()
{
    return getpid();
}

int CASProcUtil::GetCurTid()
{
    __uint64_t tid;
    pthread_threadid_np(NULL, &tid);

    return (int)tid;
}

std::string CASProcUtil::GetCurProcessName()
{
    std::string strProcessName;
    char path[512];
    unsigned size = 512;
    
    do
    {
        if(0 != _NSGetExecutablePath(path,&size) || 0 == size) break;
        
        std::string strWorkPath(path);
        std::string::size_type pos = strWorkPath.find_last_of('/');
        if (pos == std::string::npos) break;
        
        strProcessName = strWorkPath.substr(pos+1,strWorkPath.length());
    }while(false);
    
    return strProcessName;
}

std::string CASProcUtil::GetCurProcessFullPath()
{
    std::string strFullPath;
    char path[512];
    unsigned size = 512;
    
    do
    {
        if(0 != _NSGetExecutablePath(path,&size) || 0 == size) break;
        
        std::string strWorkPath(path);
        std::string::size_type pos = strWorkPath.find_last_of('/');
        if (pos == std::string::npos) break;
        
        strFullPath = strWorkPath.substr(0, pos+1);
    }while(false);
   
    return strFullPath;
}

bool CASProcUtil::IsProcessActive(long long nHandleOrId)
{
    if(kill(nHandleOrId,0)!=0)
        return true;
    else  	
        return false;
}

