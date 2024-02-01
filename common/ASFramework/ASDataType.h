//
//  ASDataType.h
//  policycom
//
//  Created by dengfan on 16/3/20.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASDataType_h
#define ASDataType_h

#ifdef __MACOSX
#define __int64 LONGLONG
#elif defined __linux__
#ifndef __int64
#define __int64 __int64_t
#endif
#endif

namespace ASDataType
{
	const long AS_VALTYPE_INT = 0;
	const long AS_VALTYPE_ASTRING = 1;
	const long AS_VALTYPE_BINARY = 2;
	const long AS_VALTYPE_WSTRING = 3;
};

#endif /* ASDataType_h */
