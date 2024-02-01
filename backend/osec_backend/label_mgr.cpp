#include "label_mgr.h"
#include "common/log/log.h"
#include "common/ini_parser.h"
#include "common/ASFramework/ASBundleImpl.hpp"
#include "common/socket_client/ISocketClientMgr.h"
#include "common/socket/socket_process_info.h"
#include "common/socket/socket_utils.h"
#include "common/singleton.hpp"
#include "common/utils/string_utils.hpp"
#include "osec_common/osec_pathmanager.h"
#include "osec_common/socket_osec.h"
#include "osec_common/osec_socket_utils.h"
#include "osec_common/log_helper.h"
#include "backend_mgr.h"
#include <dlfcn.h>

#define SECTION_ACTIVATION  "activation"
#define KEY_USER            "user"
#define KEY_PIN             "pin"

LabelMgr::LabelMgr()
{
}

LabelMgr::~LabelMgr()
{

}


int LabelMgr::Init()
{
    if (InitLog()) {
        LOG_INFO("InitLog error\n");
        return -1;
    }
    
    BACKEND_MGR->init();
    return 0;
}

int LabelMgr::InitLog()
{
    std::string strConfig = PathManager::GetInnerTXProcessPath(OSEC_BACKEND_ID) + "osec_backend.conf";
    int ret = Singleton<CLogHelper>::Instance().initByConfig(strConfig);
    if (ret) {
        LOG_INFO("init logger error");
    }
    return ret;
}
