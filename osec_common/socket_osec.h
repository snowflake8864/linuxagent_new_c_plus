
#ifndef SOCKET_SOCKET_OSEC_H_
#define SOCKET_SOCKET_OSEC_H_

namespace SocketProcessNameID {
    const long OSEC_FRONT_UI_ID = 60;                  
    const long OSEC_FILE_NET_AGENT_ID = 61;            
    const long OSEC_BUSINESS_NET_AGENT_ID = 62;        
    const long OSEC_BACKEND_ID = 63;                   
    const long OSEC_RIGHT_MENU_ID = 64;                
    const long OSEC_FRONT_UI_MISC_ID = 65;             
    const long OSEC_PASTE_MODULE_ID = 66;             
    const long OSEC_FRONT_UI_MISC_ID2 = 67;            
};

namespace SocketProcessNameStr {
    const char* const OSEC_FRONT_UI_NAME = "socket.osec.name.front_ui";
    const char* const OSEC_FILE_NET_AGENT_NAME = "socket.osec.name.file_net_agent";
    const char* const OSEC_BUSINESS_NET_AGENT_NAME = "socket.osec.name.business_net_agent";
    const char* const OSEC_BACKEND_NAME = "socket.osec.name.backend";
    const char* const OSEC_RIGHT_MENU_NAME = "socket.osec.name.right_menu";
    const char* const OSEC_FRONT_UI_MISC_NAME = "socket.osec.name.front_ui_misc";
    const char* const OSEC_PASTE_MODULE_NAME = "socket.osec.name.paste_module";
};

namespace SocketProcessUniqueID {
    const char* const OSEC_FRONT_UI_UNIQUE_ID = "socket.osec.unique_id.front_ui";
    const char* const OSEC_FILE_NET_AGENT_UNIQUE_ID = "socket.osec.unique_id.file_net_agent";
    const char* const OSEC_BUSINESS_NET_AGENT_UNIQUE_ID = "socket.osec.unique_id.business_net_agent";
    const char* const OSEC_BACKEND_UNIQUE_ID = "socket.osec.unique_id.backend";
    const char* const OSEC_RIGHT_MENU_UNIQUE_ID = "socket.osec.unique_id.right_menu";
    const char* const OSEC_FRONT_UI_MISC_UNIQUE_ID = "socket.osec.unique_id.front_ui_misc";
    const char* const OSEC_PASTE_MODULE_ID = "socket.osec.unique_id.paste_module";
};

namespace RegisterFunctionStr {
    //const char* const OSEC_REGISTER_FUNCTION_START_ANOTHER_UI = "socket.osec.events.start_another_ui"; //显示界面
    const char* const OSEC_REGISTER_FUNCTION_PROCESS_WHITE = "socket.osec.events.process_white";
    const char* const OSEC_REGISTER_FUNCTION_GET_CONF = "socket.osec.events.get_conf";
    const char* const OSEC_REGISTER_FUNCTION_DIR_POLICY = "socket.osec.events.pdir_policy";
    const char* const OSEC_REGISTER_FUNCTION_UPLOAD_LOG = "socket.osec.events.upload_log";
    const char* const OSEC_REGISTER_FUNCTION_UPLOAD_PROC_START = "socket.osec.events.upload_proc_start";
    const char* const OSEC_REGISTER_FUNCTION_PROCESS_LIST = "socket.osec.events.pocess_list";
    const char* const OSEC_REGISTER_FUNCTION_PROCESS_BLACK = "socket.osec.events.process_black";
    const char* const OSEC_REGISTER_FUNCTION_GET_EXIPORT =  "socket.osec.events.get_exiport_policy";
}

#endif /* SOCKET_SOCKET_OSEC_H_ */

