//
//  ASPcInfo.h
//  
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef ASPcInfo_h
#define ASPcInfo_h

#include <string>
#include "qh_thread/mutex.hpp"

class CASPcInfo
{
public:
	
	bool IsOS64Bit();

public:

	static std::string GetOSDetail();
	static std::string GetComputerName();

public:
	
	CASPcInfo() : m_nOSBit(-1) {}

private:

	QH_THREAD::CMutex m_initLock;
	int m_nOSBit; // -1 uninitialized,32-x86,64-x64
};

#endif //ASPcInfo_h