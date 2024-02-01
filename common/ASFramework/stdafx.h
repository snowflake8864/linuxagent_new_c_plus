// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifdef _WINDOWS
#pragma warning(disable:4996)
#pragma warning(disable:4995)
#endif

#ifdef _WINDOWS
#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <utils/osecsign.h>
#include <entclient_old/IEntClient.h>
#include <entclient_old/IPolicyControl.h>
#include <entclient_old/IEntCommAgent.h>
#include <entclient_old/IReportControl.h>
#include <entclient_old/ipc/IMsgCenter.h>
#include <entclient_old/IEntModularize.h>
extern HMODULE g_hInstance;
#else
#include "includes.h"
#endif

#include <string>
#include <vector>
#include <list>
#include <map>
using namespace std;

#include "ASFramework/ASFoundation.h"
#include "ASFramework/ASBundleImpl.hpp"
#include "ASFramework/util/ASLogImpl.h"
#include "ASFramework/util/ASJsonWrapper.h"
#include "ASFramework/util/ASProcUtil.h"
#include "ASFramework/util/ASTrustVerify.h"
#include "ASFramework/conf/ASAuthControlConfKey.h"
#include "ASFramework/util/ASCodeHelper.h"
#include "log/log.h"

using namespace ASCore;
using namespace ASFramework;
using namespace ASContentClass;
using namespace ASBundleHelper;
using namespace ASReportCom;
using namespace ASFrameworkOper;
using namespace ASAuthorityControl;
using namespace ASAuthControlConfKey;