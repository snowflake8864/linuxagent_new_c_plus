#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

// trun to deamon process
int becomeDeamon(const char *path) {
    switch (fork()) {
        case -1:
            return -1;  // error
        case 0:
            break;  // child
        default:
            _exit(0);  // parent
    }

    if (setsid() == -1)  // Become leader of new session
        return -1;

    switch (fork()) {
        case -1:
            return -1;
        case 0:
            break;
        default:
            _exit(0);  // parent
    }

    umask(0);  // clean umaks, make sure file creation works ok

    {
        int ignore = chdir(path);
        (void)ignore;
    }  // set work dir

    for (int fd = 0; fd < 3; fd++) close(fd);
    if (open("/dev/null", O_RDWR) != STDIN_FILENO) return -1; // keep STD_  to null
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) return -1;
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) return -1;

    return 0;
}
