#ifndef PORT_MGR
#define PORT_MGR

#include <string>
#include <unistd.h>
#include <vector>
#include "osec_common/global_message.h"


class CPORT_MGR{
public:
    static int GetPortBusiness(std::vector<PORT_BUSINESS_LIST> &lstPortBus);
    static int SetVirtualPort(const std::vector<PORT_REDIRECT> &lstPortRed);
 
    static int UpdateBusinessPort(void);
};


#endif
