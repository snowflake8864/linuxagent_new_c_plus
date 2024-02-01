//
//  ASOperator.h
//
//
//  Created by dengfan on 16/4/14.
//  Copyright © 2016年 dengfan. All rights reserved.
//

#ifndef ASExtOperater_h
#define ASExtOperater_h

#include "ASErrCode.h"
#include "ASBundle.h"

class IASExtOperater : public IASBundle
{
public:
	virtual ASCode CreateBundle(OUT IASBundle** lppBundle) = 0;
	virtual ASCode ReportData(IN OUT IASBundle* pParam) = 0;
	virtual ASCode ReportData(const char* lpszType,unsigned char* lpContent,int nContLen) = 0;
};

namespace ASFrameworkExtOper
{
	//////////////////////////////////////////////////////////////////////////
	//ExtOperater自身的各种属性,都是utf8字符串,可以用bundle的getAString接口获取
};

typedef IASExtOperater* (__stdcall FCreateASExtOperator)(IASFramework*,IASBundle* pData);
extern "C" IASExtOperater* __stdcall CreateASExtOperator(IASFramework* pFramework, IASBundle* pData);
#endif /* ASExtOperater_h */
