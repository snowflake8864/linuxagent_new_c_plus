#include "signal_handle.h"
#include "log/log.h"

sig_atomic_t CSignalHandler::m_quit = 0;

void CSignalHandler::install_signal_handler() {
    struct sigaction act;
    // clear block signal
    sigemptyset(&act.sa_mask);
    // set transist extra param to handler function
    act.sa_flags = SA_SIGINFO;
    // set signal handler function
    act.sa_sigaction = CSignalHandler::exit_signal_handler;

    // install signal handler to process SIGTERM
    if (sigaction(SIGTERM, &act, NULL) < 0) {
        LOG_ERROR("install SIGTERM signal handler failed!")
    }
    // install signal handler to process SIGTERM
    if (sigaction(SIGABRT, &act, NULL) < 0) {
        LOG_ERROR("install SIGABRT signal handler failed!")
    }
    // install signal handler to process SIGTERM
    if (sigaction(SIGINT, &act, NULL) < 0) {
        LOG_ERROR("install SIGINT signal handler failed!")
    }
}

void CSignalHandler::exit_signal_handler(int n, siginfo_t *siginfo, void *myact) {
    int sig = siginfo->si_signo;
    if (sig == SIGTERM || sig == SIGINT || sig == SIGABRT) {
        m_quit = 1;
    }
}
