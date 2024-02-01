#ifndef NET_MGR
#define NET_MGR

#include <string>
#include <unistd.h>
#include <vector>
#include "osec_common/global_message.h"


class CNet_MGR{
public:
    int SetNetWhitePolicy(std::vector<NET_PROTECT_IP> &lstNetIP);
    int SetNetBlackPolicy(std::vector<NET_PROTECT_IP> &lstNetIP);
    int SetNetRedirect(std::vector<PORT_REDIRECT> &lstNetIP);
    int SetNetBlockList(std::vector<NETBLOCK> &lstNetIP);
    int GetNetPolicy(std::vector<FirewallRule>& lstFireWall);
};


#endif
