#ifndef ASNetFlowMgr_h
#define ASNetFlowMgr_h

class IASNetFlowMgr : public IASFrameworkService
{
public:

	virtual ASCode Init() = 0;

	virtual ASCode ReloadConf() = 0;

	virtual ASCode CreateInstance(const char* clsid, void** ppInterface) = 0;

	//申请流量配额，lpParams中应传入流向（上传、下载）、进程id、业务标识（combo）、是否自动分配、配额值（自动分配的情况下这个值无效） 
	virtual ASCode ApplyQuota(IASOperaterBase* lpOper,IASBundle* lpParams) = 0; 

	//归还流量配额
	virtual ASCode ReturnQuota(IASOperaterBase* lpOper,IASBundle* lpNetQuota) = 0;

	virtual ASCode UnInit() = 0;
};

namespace ASNetFlowMgr
{
	//(type int)申请者所在进程的pid
	const char* const AS_NETFLOWMGR_ATTR_PID	= "as.netflowmgr.attr.pid";

	//(type string)申请下载的业务类型，mgr根据业务类型分配流量
	const char* const AS_NETFLOWMGR_ATTR_APPLY_TYPE	= "as.netflowmgr.attr.apply_type";

	//(type string)目的服务器类型，mgr根据业务类型判断是否限流，为空一定限流
	const char* const AS_NETFLOWMGR_ATTR_SERVER_TYPE	= "as.netflowmgr.attr.server_type";

	//(type int)申请流量大小
	const char* const AS_NETFLOWMGR_ATTR_APPLY_FLOWS	= "as.netflowmgr.attr.apply_flows";

	//(type int)申请分配到的流量大小
	const char* const AS_NETFLOWMGR_ATTR_DIVIDE_FLOWS	= "as.netflowmgr.attr.divide_flows";

	//(type int)申请流量方向（上传或者下载）
	const char* const AS_NETFLOWMGR_ATTR_FLOW_DIRECTION  = "as.netflowmgr.attr.flow_direction";
	
	
	const int AS_NetFlowMgrFlowDirection_Upload = 0; //上传
	const int AS_NetFlowMgrFlowDirection_Download = 1;	//下载
	const char* const AS_NETFLOWMGR_LOG_FILTER = "as.log.netflowmgr";
};

namespace ASNetFlowMgrConf
{
	const char* const AS_NETFLOWMGR_CONF_LIMIT_TIME_LIST			= "limit_time_list";
	const char* const AS_NETFLOWMGR_CONF_LIMIT_DOWNLOST_SETTING		= "limit_download";
	const char* const AS_NETFLOWMGR_CONF_LIMIT_MAX_SPEED			= "limit_download_max_speed";
	const char* const AS_NETFLOWMGR_CONF_LIMIT_WHITE_SERVERS		= "white_servers";
}

#endif //ASNetFlowMgr_h
