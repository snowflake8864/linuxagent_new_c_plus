//
//  ASErrCode.h
//  asframework
//
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASErrCode_h
#define ASErrCode_h

typedef long ASCode;

#define ASErr_OK							0x0
#define ASErr_ABORT							0x80004004L
#define ASErr_NOIMPL						0x80004001L
#define ASErr_FAIL							0x80040005L
#define ASErr_INVALIDARG					0x80070057L
#define ASErr_OUTOFMEMORY					0x8007000EL
#define ASErr_INSUFFICIENT_BUFFER			201
#define ASErr_BUSY							170L

#define ASErr_TIMEOUT						500L		//超时错误码

#define ASErr_NOTFIND						501L		//未找到错误码，例如发送ipc到指定端点，端点未找到，返回该错误

#define ASErr_IPC_REGISTER_FAILED			502L		//IPC注册失败错误码

#define ASErr_REPORT_FILTER_INTERRUPT		503L

#define ASErr_UNKNOWN_IPC_MSG				504L		//未知的IPC消息

#endif /* ASErrCode_h */
