//
//  IASUnknown.h
//  
//
//  Created by dengfan on 16/3/18.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef IASUnknown_h
#define IASUnknown_h

#include "ASErrCode.h"

class IASUnknown
{
public:
    
    virtual ASCode	QueryInterface(const char* pszClsid,void** ppInterface) = 0;
    virtual long	AddRef() = 0;
    virtual long	Release() = 0;
};

#if (defined _WINDOWS) || (defined WIN32) || (defined WIN64)
#define ASUNKNOWN_EASY_IMPLEMENT(theClass)\
public:\
	virtual ASCode	QueryInterface(const char* pszClsid, void** ppInterface) { return ASErr_NOIMPL; }\
	virtual long	AddRef() { return InterlockedIncrement(&m_lRefCount_##theClass); }\
	virtual long	Release() { long l = InterlockedDecrement(&m_lRefCount_##theClass); if (l == 0) delete this; return l; }\
private:\
	long m_lRefCount_##theClass;
#else
#define ASUNKNOWN_EASY_IMPLEMENT(theClass)\
public:\
	virtual ASCode	QueryInterface(const char* pszClsid, void** ppInterface) { return ASErr_NOIMPL; }\
	virtual long	AddRef() { __sync_fetch_and_add(&m_lRefCount_##theClass, 1); return m_lRefCount_##theClass; }\
	virtual long	Release() { __sync_fetch_and_sub(&m_lRefCount_##theClass, 1); if (0 == m_lRefCount_##theClass) delete this; return m_lRefCount_##theClass; }\
private:\
	volatile long m_lRefCount_##theClass;
#endif

#endif /* IASUnknown_h */
