//
//  ASFuncAgent.h
//  ASFuncAgent
//
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASFuncAgent_h
#define ASFuncAgent_h


#ifdef _WINDOWS
#define ASatoi64 _atoi64
#define ASwtoi64 _wtoi64
#define ASDlOpen(dllPath) LoadLibraryA(##dllPath)
#ifdef _DEBUG
#define ASDlOpen_qs(dllPath) LoadLibraryA(##dllPath)
#else
#define ASDlOpen_qs(dllPath) LoadLibrary_qs(CA2W(dllPath))
#endif
#define ASDlSym(hMod,ProcName)  GetProcAddress((HMODULE)##hMod,##ProcName)
#define ASIsTrustedFile(filePath) CheckosecSign(##filePath)
#define ASDlClose(hMod) FreeLibrary((HMODULE)##hMod)

#else
#define ASatoi64 atoll
#define ASwtoi64 wtoll
#define ASDlOpen(dllPath) dlopen(dllPath,RTLD_LAZY)
#define ASDlOpen_qs(dllPath) dlopen(dllPath,RTLD_LAZY)
#define ASDlSym  dlsym
#define ASIsTrustedFile(filePath) (filePath)
#define ASDlClose(hMod) dlclose(hMod)
#endif

#endif
