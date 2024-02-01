//
//  ASFuncProvider.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASFuncProvider_h
#define ASFuncProvider_h

class IASActionResultReceiver
{
public:
	
	virtual long OnActionResult(IASBundle* pResult) = 0;
};

class IASFuncProvider
{
public:
	
	virtual ASCode OnActionRequest(IASBundle* pRequest) = 0;

	virtual ASCode OnActionRequestForResult(IASBundle* pRequest,IASBundle* pResult) = 0;

	virtual ASCode OnActionRequestForResultAsync(IASBundle* pRequest,IASActionResultReceiver* pReceiver) = 0;
};

class IASFuncProviderMgr
{
public:

	virtual ASCode RegisterProvider(IASOperaterBase* pOper,const char* lpszFunc,IASFuncProvider* lpProvider) = 0;
	virtual ASCode UnRegisterProvider(IASOperaterBase* pOper,const char* lpszFunc,IASFuncProvider* lpProvider) = 0;

	virtual ASCode RequestAction(IASOperaterBase* pOper, const char* lpszFunc) = 0;
	virtual ASCode RequestActionForResult(IASOperaterBase* pOper, const char* lpszFunc, IASBundle* pResult) = 0;
	virtual ASCode RequestActionForResultAsync(IASOperaterBase* pOper, const char* lpszFunc, IASActionResultReceiver* pResultRecver) = 0;
};

#endif /* ASFuncProvider_h */
