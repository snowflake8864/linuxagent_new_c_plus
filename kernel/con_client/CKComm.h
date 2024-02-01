#ifndef TQ_CKCOMM_H
#define TQ_CKCOMM_H

namespace CKComm {
    void set_fd_cloexec(int fd);
    void set_fd_nonblock(int fd);
};

#endif