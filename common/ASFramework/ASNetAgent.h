//
//  ASNetAgent.h
//  asframework
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASNetAgent_h
#define ASNetAgent_h

#include "ASFoundation.h"

class INetAgentEventNotify
{
public:
	virtual void OnNetAgentEvent(const char* lpszEvent, IASBundle* lpEventData) = 0;
};

__servicename(IASNetAgent, "as.svc.netagent")
class IASNetAgent : public IASFrameworkService
{
public:

	virtual ASCode Init() = 0;
	virtual ASCode ReloadConf() = 0;
	virtual ASCode CreateInstance(const char* clsid, void** ppInterface) = 0;
	virtual ASCode SendData(IASOperaterBase* pOper, IN IASBundle* pInData, OUT IASBundle* pOutData) = 0;
	virtual ASCode SendCriticalData(IASOperaterBase* pOper, IN IASBundle* pInData, OUT IASBundle* pOutData) = 0;
	virtual ASCode SubscribeNetEvent(IASOperaterBase* pOper, const char* lpszEvent, INetAgentEventNotify* pNotifyCb) = 0;
	virtual ASCode UnSubscribeNetEvent(IASOperaterBase* pOper, const char* lpszEvent, INetAgentEventNotify* pNotifyCb) = 0;

	virtual ASCode CallFunction(IASOperaterBase* pOper, IN IASBundle* pInData, OUT IASBundle* pOutData) { return ASErr_NOIMPL; }
};

namespace ASNetAgent
{
	//////////////////////////////////////////////////////////////////////////
	//可以通过IASNetAgent的Subscribe接口获取到的通讯事件通知
	//订阅心跳内容，返回服务端心跳接口返回的内容
	const char* const ASNetAgentEvent_Heartbeat = "as.netagent.event.heartbeat";
	//控制中心ip变化，返回新的控制中心地址，ip:port的格式
	const char* const ASNetAgentEvent_ConsoleServerChange = "as.netagent.event.ConsoleServerChange";
	//和控制中心联通性变化，1为正常连接，0为连接断开
	const char* const ASNetAgentEvent_ConnectStatusChange = "as.netagent.event.ConnectStatusChange";
	//和互联网联通性变化，1为正常连接，0为连接断开
	const char* const ASNetAgentEvent_InternetConnectStatusChange = "as.netagent.event.InternetConnectStatusChange";
	//收到了长连接推送的实时任务，返回任务内容
	const char* const ASNetAgentEvent_TaskFromLonglinkArrive = "as.netagent.event.TaskFromLonglinkArrive";

	//INetAgentEventNotify的lpEventData bundle里保存的事件数据
	const char* const ASNetAgentEvent_ContentData = "as.netagent.event.content_data";

	//////////////////////////////////////////////////////////////////////////
	//网络协议定义，为了和老版本兼容，用这样的名称
	//1.0协议，不做任何处理；2.0协议，做了变换、压缩
	const char* const AS_NETAGENT_PROTOCOL_10 = "1.0";
	const char* const AS_NETAGENT_PROTOCOL_20 = "2.0";
	//////////////////////////////////////////////////////////////////////////
	//通讯属性默认值的声明，conf文件里也有配置
	//通讯的默认超时时间，单位为毫秒
	const unsigned int AS_NETAGENT_DEFAULT_SEND_TIMEOUT = 45 * 1000;
	//通讯的url最大长度，单位字节
	const int AS_NETAGENT_MAX_URL_LEN = 4 * 1024;
	//log的过滤器,内部使用
	const char* const AS_NETAGENT_LOG_FILTER = "as.log.netagent";
	//log的过滤器,内部使用
	const char* const AS_NETAGENT_MIDLOG_FILTER = "as.log.netagent_mid";
	//通讯方式，httpGet和httpPost
	const unsigned int ASNetAgentSendMethod_MIN = 0;
	const unsigned int ASNetAgentSendMethod_HTTPGET = 0;
	const unsigned int ASNetAgentSendMethod_HTTPPOST = 1;
	const unsigned int ASNetAgentSendMethod_MAX = 1;

	const unsigned int ASNetAgentContentType_Buffer = 0;
	const unsigned int ASNetAgentContentType_File = 1;
	//////////////////////////////////////////////////////////////////////////
	//通讯参数，在SendData或SendCriticalData的pInData Bundle里传入的各种参数
	//和天擎控制中心通讯只需要指定AS_NETAGENT_SENDATTR_API、AS_NETAGENT_SENDATTR_CONTENT即可
	//netagent模块会自动拼接url，并在后面加上终端mid、通讯version等参数
	//通讯方式，int.只支持ASNetAgentSendMethod_HTTPGET和ASNetAgentSendMethod_HTTPPOST，默认为post
	const char* const AS_NETAGENT_SENDATTR_METHOD = "as.netagent.senddata.attr.send_method";
	//通讯api，类似 api/heartbeat.json这种，utf8 string
	const char* const AS_NETAGENT_SENDATTR_API = "as.netagent.senddata.attr.api";
	//通讯时要发送的数据，binary.HTTPPOST时会填在http body部分,HTTPGET时忽略
	const char* const AS_NETAGENT_SENDATTR_CONTENT = "as.netagent.senddata.attr.content";
	//通讯的超时时间,int,单位毫秒，默认值为AS_NETAGENT_DEFAULT_SEND_TIMEOUT
	const char* const AS_NETAGENT_SENDATTR_TIMEOUT = "as.netagent.senddata.attr.timeout";
	//和天擎控制中心外的服务器通讯需要指定AS_NETAGENT_SENDATTR_ADDRESS或AS_NETAGENT_SENDATTR_RAWURL
	//区别为只指定AS_NETAGENT_SENDATTR_ADDRESS时还会自动补全url，加上mid、ver等参数，一般用于和天擎的盒子产品通讯
	//指定AS_NETAGENT_SENDATTR_RAWURL时url参数完全用自定义值，一般用于和天擎体系外的服务器通讯
	//通讯的完整url，utf8 string
	const char* const AS_NETAGENT_SENDATTR_RAWURL = "as.netagent.senddata.attr.url";
	//额外uri，类似http://127.0.0.1/download/setup/1.7z后面的download/setup/1.7z部分，utf8 string，最大4k
	const char* const AS_NETAGENT_SENDATTR_EXTRAURI = "as.netagent.senddata.attr.extra_uri";
	//通讯地址，类似10.18.31.87:8080这种格式，不指定时默认用控制中心地址，暂不支持域名
	const char* const AS_NETAGENT_SENDATTR_ADDRESS = "as.netagent.senddata.attr.address";
	//通讯时使用的终端mid，一般不需要自己指定，不指定时用天擎默认值
	const char* const AS_NETAGENT_SENDATTR_MID = "as.netagent.senddata.attr.mid";
	//通讯时强制使用1.0协议，int值，1-强制使用1.0协议；0-默认值，随着配置文件自动切换1.0/2.0协议，常使用于外网弹窗、第三方不支持ver=2.0参数的场景
	const char* const AS_NETAGENT_SENDATTR_PROTOCOL10 = "as.netagent.senddata.attr.protocol_10";
	//通讯的时候保持一段时间的连接，int值（0-默认值，不使用；1-使用），可节省创建和断开连接时的流量消耗，适用连续（1 min内）使用同一接口的场景
	const char* const AS_NETAGENT_SENDATTR_KEEPALIVE = "as.netagent.senddata.attr.keepalive";
	
	//上传内容的属性目前可能是buffer或者file
	const char* const AS_NETAGENT_SENDATTR_CONTENT_TYPE = "as.netagent.senddata.attr.content_type";
	//http请求头，格式key1:val1\r\nkey2:val2\r\nkey3:val3
	const char* const AS_NETAGENT_SENDATTR_HEADERS = "as.netagent.senddata.attr.headers";
	//////////////////////////////////////////////////////////////////////////
	//通讯返回值，在SendData或SendCriticalData的pOutData Bundle里返回
	//通讯返回http code，int
	const char* const AS_NETAGENT_SENDRELT_HTTPCODE = "as.netagent.senddata.result.httpcode";
	//netagent的内部错误码，int
	const char* const AS_NETAGENT_SENDRELT_ASERRCODE = "as.netagent.senddata.result.aserrcode";
	//服务端返回数据，binary
	const char* const AS_NETAGENT_SENDRELT_SERVRET = "as.netagent.senddata.result.servret";
	//服务端返回数据的长度，int
	const char* const AS_NETAGENT_SENDRELT_SERVRETLEN = "as.netagent.senddata.result.servret_len";

	//////////////////////////////////////////////////////////////////////////netagent的Function Provider
	// CallFunction的pInData中存放的参数值, char
	// 简单心跳{"type": "heartbeat.simple", "src": "xxxx.ext", "data": {"dest": "xxx.com"}}
	//          {"type": "heartbeat.simple", "src": "asnetagent", "data": {"result":"1","httpcode":"200/304"}}
	// 简单注册{"type": "register.simple", "src": "xxxxx.ext", "data": {"dest": "xxx.com"}}
	//          {"type": "register.simple", "src": "asnetagent", "data": {"result":"1","httpcode":"200/304"}}
	const char* const AS_NETAGENT_FUNCTION_IN_PARAM = "as.netagent.function.in.param";
	// CallFunction的pOutData中存放的返回结果, char
	const char* const AS_NETAGENT_FUNCTION_OUT_CONTENT = "as.netagent.function.out.content";
	// 简单心跳
	const char* const AS_NETAGENT_FUNCTION_HEARTBEAT_SIMPLE = "heartbeat.simple";
	// 简单注册
	const char* const AS_NETAGENT_FUNCTION_REGISTER_SIMPLE = "register.simple";

	//////////////////////////////////////////////////////////////////////////
	//netagent的内部属性，请求的目的地址
	const char* const AS_NETAGENT_ATTR_SERV_INFO = "as.netagent.attr.serv_info";
	//netagent的内部属性，可用连接数，int
	const char* const AS_NETAGENT_ATTR_AVAILABLE_CONNECTION = "as.netagent.attr.max_connection";	
	//netagent的内部属性，控制中心迁移目标，格式为ip：port,utf8 string
	const char* const AS_NETAGENT_ATTR_MIGRATE_INFO = "as.netagent.attr.migrate_info";
	//netagent的内部属性，是否使用共享内存，建行绿色版共存需求增加，临时方案
	const char* const AS_NETAGENT_ATTR_NO_SHAREMEM = "as.netagent.attr.no_sharemem";	
	//netagent的内部属性，是否检查单实例，建行绿色版共存需求增加，临时方案
	const char* const AS_NETAGENT_ATTR_SINGLE_INSTANCE = "as.netagent.attr.single_instance";
	//netagent的内部属性，无心跳模块，不会向控制中心注册发送心跳，只作为其他模块向控制台通信模块
	const char* const AS_NETAGENT_ATTR_NO_HEARTBEAT = "as.netagent.attr.no_heartbeat";
};

typedef IASNetAgent* (__stdcall FNCreateASNetAgent)(IN IASFramework* lpFramework);
#if (defined _WINDOWS) || (defined WIN32)
extern "C" __declspec(dllexport) IASNetAgent* __stdcall CreateASNetAgent(IN IASFramework* lpFramework);
#endif

#endif //ASNetAgent_h
