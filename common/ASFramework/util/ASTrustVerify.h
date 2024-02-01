//
//  ASTrustVerify.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASTrustVerify_h
#define ASTrustVerify_h

#include <string>

class CASTrustVerify
{
public:
	
	static bool IsTrustedFile(const char* lpszFile);

	//验证文件是否有360签名
	static bool Is360SignedFile(const char* lpszFile);

private:

};

#endif //ASPcInfo_h
