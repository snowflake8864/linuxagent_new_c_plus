#include <unistd.h>
#include <fcntl.h>
#include "CKComm.h"

namespace CKComm {
    void set_fd_cloexec(int fd)
    {
        int flags = 0;
        flags = fcntl(fd,F_GETFD);
        if(flags >= 0) {
            flags |= FD_CLOEXEC;
            fcntl(fd,F_SETFD,flags);
        }
    }

    void set_fd_nonblock(int fd)
    {
        int flags = fcntl(fd,F_GETFL);
        if(flags >= 0) { 
            flags |= O_NONBLOCK;
            fcntl(fd,F_SETFL,flags);
        }
    }
};