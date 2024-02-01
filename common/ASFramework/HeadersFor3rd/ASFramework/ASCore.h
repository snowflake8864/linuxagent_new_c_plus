//
//  ASCore.h
//  asframework
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASCore_h
#define ASCore_h

#include "ASFoundation.h"

class IASOperaterBase;
class IASExtOperater;

typedef  bool __stdcall FExtInitASFramework(OUT IASExtOperater** lppOperator);
extern "C" __declspec(dllexport) bool __stdcall ExtInitASFramework(OUT IASExtOperater** lppOperator);

#endif //ASCore_h