//
//  comm_action.h
//  modularize
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef comm_action_h
#define comm_action_h

#include "ASBundleImpl.hpp"

class IASCommonAction : public IASBundle
{
public:

	ASBUNDLE_EASY_IMPLEMENT(IASCommonAction)

public:
	virtual ASCode	QueryInterface(const char* pszClsid, void** ppInterface) { return ASErr_NOIMPL; }
	virtual long	AddRef() { __sync_fetch_and_add(&m_lRefCount, 1); return m_lRefCount; }
	virtual long	Release() { __sync_fetch_and_sub(&m_lRefCount, 1); if (0 == m_lRefCount) delete this; return m_lRefCount; }

public:

	IASCommonAction() : m_lRefCount(0) {}
	
	virtual ~IASCommonAction() { clear(); }

	virtual const char* GetType() = 0;

	virtual ASCode Execute() = 0;

	virtual void Set3rd(bool b3rd = false, const char* chVer = NULL) = 0;

private:
	volatile long m_lRefCount;
};

class CASCommonActionExecutor
{
public:
	CASCommonActionExecutor() : m_bSunccess(true) { }
	void operator()(IASCommonAction* pAction)
	{
		if(!pAction || ASErr_OK != pAction->Execute())
			m_bSunccess = false;
	}

	bool ExecSuccess() const {return m_bSunccess;}

private:

	bool m_bSunccess;
};

#endif //comm_action_h