#include "utils/breakpad_utils.h"
#include <stdlib.h>
#include <string>
#include "breakpad/client/linux/handler/exception_handler.h"

namespace breakpad_utils {

static bool dumpCallback(const google_breakpad::MinidumpDescriptor &descriptor,
             void *context, bool succeeded)
{
    printf("Dump path: %s\n", descriptor.path());
    char cmd[512] = {0};
    snprintf(cmd, sizeof(cmd), "echo %s > /tmp/dump_name", descriptor.path());
    int rtn = system(cmd);
    return succeeded;
}

void breakpad_init(const std::string &strCoreFilePath)
{
    static google_breakpad::MinidumpDescriptor descriptor(strCoreFilePath.c_str());
    static google_breakpad::ExceptionHandler eh(descriptor,
                         NULL,
                         dumpCallback,
                         NULL,
                         true,
                         -1);
    return ;
}

}
