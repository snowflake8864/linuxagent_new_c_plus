//
//  ASNetDefine.h
//  policycom
//
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASNetDefine_h
#define ASNetDefine_h

typedef int ASNetCode;

//网络通讯的内部错误码
#define ASNetError_Success					0x0
#define ASNetError_Timeout					0x1
#define ASNetError_InvalidParam				0x2
#define ASNetError_NotRegistered			0x3
#define ASNetError_InternalError			0x4
#define ASNetError_InsufficientFlow			0x5
#define ASNetError_InsufficientConnection	0x6
#define ASNetError_EncodeError				0x7
#define ASNetError_ParseError				0x8
#define ASNetError_NotFound					0x9

//http错误码
#define AS_HTTP_STATUS_OK                  200 // request completed
#define AS_HTTP_STATUS_CREATED             201 // object created, reason = new URI
#define AS_HTTP_STATUS_ACCEPTED            202 // async completion (TBS)
#define AS_HTTP_STATUS_PARTIAL             203 // partial completion
#define AS_HTTP_STATUS_NO_CONTENT          204 // no info to return
#define AS_HTTP_STATUS_RESET_CONTENT       205 // request completed, but clear form
#define AS_HTTP_STATUS_PARTIAL_CONTENT     206 // partial GET furfilled
#define AS_HTTP_STATUS_NOT_MODIFIED        304 // if-modified-since was not modified
#define AS_HTTP_STATUS_BAD_REQUEST		   400 // invalid syntax
#define AS_HTTP_STATUS_DENIED              401 // access denied
#define AS_HTTP_STATUS_FORBIDDEN           403 // request forbidden
#define AS_HTTP_STATUS_NOT_FOUND           404 // object not found
#define AS_HTTP_STATUS_SERVER_ERROR        500 // internal server error
#define AS_HTTP_STATUS_NOT_SUPPORTED       501 // required not supported
#define AS_HTTP_STATUS_SERVICE_UNAVAIL     503 // temporarily overloaded

#endif /* ASNetDefine_h */
