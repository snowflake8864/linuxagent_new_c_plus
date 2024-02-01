#ifndef BACKEND_NET_AGENT_REPORT_DATA_CONTROL_HPP_
#define BACKEND_NET_AGENT_REPORT_DATA_CONTROL_HPP_

#include <string.h>
#include <new>
#include "common/json/cJSON.h"

#define ReportTimeout_Default 10
#define ReportKeyContent "report_content"
#define ReportKeyContLen "report_contlen"
#define ReportKeyDest "report_dest"
#define ReportKeyMethod "report_method"
#define ReportKeySync "report_sync"
#define ReportKeyCritical "report_critical"
#define ReportKeyTimeout "report_timeout"
#define ReportKeyHttpCode "report_httpcode"
#define ReportKeyType "report_type"
#define ReportKeyUser "report_user"

enum ReportMethod
{
    kReportMethodGET = 1,
    kReportMethodPOST,
    kReportMethodMax = 50
};

#endif /* BACKEND_NET_AGENT_REPORT_DATA_CONTROL_HPP_ */