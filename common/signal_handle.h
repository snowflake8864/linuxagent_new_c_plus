#ifndef SIGNAL_HANDLE_H_
#define SIGNAL_HANDLE_H_

#include <signal.h>

class CSignalHandler {
  public:
    CSignalHandler() {}
    ~CSignalHandler(){}

  public:
    static void install_signal_handler();
    static void exit_signal_handler(int n, siginfo_t *siginfo, void *myact);
    static bool quit() { return (m_quit != 0); }

  private:
    static sig_atomic_t m_quit;
};

#endif /* SIGNAL_HANDLE_H_ */