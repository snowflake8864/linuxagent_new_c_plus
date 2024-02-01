#include <string>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <signal.h>
#include "common/socket_server/ISocketServerMgr.h"
#include "osec_common/osec_pathmanager.h"
#include "osec_common/socket_osec.h"
#include "common/socket/socket_process_info.h"
#include "osec_common/global_config.hpp"

static void* dl_handler = NULL;
static ISocketServerMgr* p_socket_server = NULL;

void CreateInstance(const char* dl_path, const char* config) {
    dl_handler = dlopen(dl_path, RTLD_LAZY);
    if (!dl_handler) { 
        fprintf(stderr,"dlopen %s failed: %s.\n", dl_path, dlerror());
        return;
    }

    dlerror();
    FCreateInstance fn = (FCreateInstance)dlsym(dl_handler, "CreateInstance");
    if(!fn) {
        fprintf(stderr,"dlsym CreateInstance failed: %s.\n", dlerror());
        dlclose(dl_handler);
        return;
    }
    p_socket_server = fn(config);
}

static void signal_exit_handler(int sig) {
    fprintf(stderr,"recv sig = [%d], main process exit.\n", sig);
    p_socket_server->StopLoop();
}

int main(int argc,char* argv[])
{
    signal(SIGINT,  signal_exit_handler); /* Interactive attention signal.  */
    signal(SIGILL,  signal_exit_handler); /* Illegal instruction.  */
    signal(SIGABRT, signal_exit_handler); /* Abnormal termination.  */
    signal(SIGTERM, signal_exit_handler); /* Termination request.  */
    signal(SIGKILL, signal_exit_handler); /* Termination request.  */

    std::string strConfig = PathManager::GetInnerTXProcessPath(OSEC_BACKEND_ID) + "osec_server.conf";
    std::string dl_path = INSTALL_PATH;
    dl_path +="libOsecEngSvr.so";
    CreateInstance(dl_path.c_str(), strConfig.c_str());

    if (!p_socket_server) { return -1; }
    p_socket_server->RunLoop();
    p_socket_server->Release();
    dlclose(dl_handler);
    return 0;
}

