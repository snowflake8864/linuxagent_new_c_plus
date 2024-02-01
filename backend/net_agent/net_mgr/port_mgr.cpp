#include "port_mgr.h"
#include <sys/stat.h>
#include <pwd.h>
#include "common/md5sum.h"
#include "common/utils/string_utils.hpp"
#include "netstate.h"

int CPORT_MGR::GetPortBusiness(std::vector<PORT_BUSINESS_LIST> &lstPortBus) {
    CPortInfo netmgr;
    netmgr.getportinfo(lstPortBus);
    return 0;
}

int CPORT_MGR::SetVirtualPort(const std::vector<PORT_REDIRECT> &lstPortRed) {
    //CPortInfo netmgr;
   // netmgr.SetNetRedirect(lstPortRed);
    return 0;
}


int CPORT_MGR::UpdateBusinessPort(void)
{
    CPortInfo *netmgr = CPORTINFO;
    netmgr->getNetstatinfo();
    return 0;
}
