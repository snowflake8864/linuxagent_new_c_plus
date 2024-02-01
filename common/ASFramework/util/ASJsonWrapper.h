//
//  as_json_wrapper.hpp
//
//
//  Created by dengfan on 16/4/14.
//  Copyright © 2016年 dengfan. All rights reserved.
//

#ifndef as_json_wrapper_hpp
#define as_json_wrapper_hpp

/// 注意下面两文件的路径，必须在工程包含
#include <fstream>
#include <string>
using namespace std;

#if (defined _WINDOWS) ||(defined WIN32)
#include <atlconv.h>
#endif

#ifdef __linux__
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#endif

#include "json/json.h"
//#pragma comment(lib,"json_vc90_libmt-s-0.10.6_x64.lib")
#ifndef _WIN64
	#if (defined _WINDOWS) || (defined WIN32)
		#ifdef _DEBUG
			#if _MSC_VER == 1500
				#pragma comment(lib,"json_vc90_libmt-sgd-0.10.6.lib")
			#else if _MSC_VER >= 1900
				#pragma comment(lib,"json_vc140_libmt-sgd-0.10.6.lib")
			#endif
		#else
			#if _MSC_VER == 1500
				#pragma comment(lib,"json_vc90_libmt-s-0.10.6.lib")
			#else if _MSC_VER >= 1900
				#pragma comment(lib,"json_vc140_libmt-s-0.10.6.lib")
			#endif
		#endif	//endif _DEBUG
	#endif	//endif _WINDOWS || WIN32
#else
	#ifdef _DEBUG
		#if _MSC_VER == 1500
			#pragma comment(lib,"json_vc90_libmt-sgd-0.10.6_x64.lib")
		#else if _MSC_VER >= 1900
			#pragma comment(lib,"json_vc140_libmt-sgd-0.10.6_x64.lib")
		#endif
	#else
		#if _MSC_VER == 1500
			#pragma comment(lib,"json_vc90_libmt-s-0.10.6_x64.lib")
		#else if _MSC_VER >= 1900
			#pragma comment(lib,"json_vc140_libmt-s-0.10.6_x64.lib")
		#endif
	#endif	//endif _DEBUG
#endif	//endif WIN64

class CASJsonWrapper
{
public:

	static bool LoadJsonFile(const char* lpFile,Json::Value& jvRoot)
	{
		if (!lpFile || strlen(lpFile) <= 0)
			return false;

		try
		{
			Json::Reader jsReader;
			jvRoot = Json::Value(Json::nullValue);
			std::ifstream jsFileStream;
#if (defined _WINDOWS) || (defined WIN32)
			jsFileStream.open(CA2W(lpFile),ios::in);	//windows路径使用Unicode编码
#else
			jsFileStream.open(lpFile,ios::in);	//Linux和Mac使用默认的UTF8编码
#endif
			bool rtn = jsReader.parse(jsFileStream,jvRoot);
			jsFileStream.close();
			return rtn;
		}
		catch(...) { return false;}
	}

	static bool LoadJsonString(const std::string& strJString,Json::Value& jvRoot)
	{
		if(strJString.empty())	return false;
		try
		{
			Json::Reader jsReader;
			jvRoot = Json::Value(Json::nullValue);
			return jsReader.parse(strJString,jvRoot);
		}
		catch(...) { return false;}
	}

	static bool WriteJsonToFile(const char* lpszFile,const Json::Value &jvRoot)
	{
		if(!lpszFile || strlen(lpszFile) <= 0)
			return false;

		try
		{
			std::string strFileBak = lpszFile;
			strFileBak += "_bak"; // 任何需要写入的文件先将其写入bak临时文件
			Json::StyledWriter jsWriter;
			std::string strBuff = jsWriter.write(jvRoot);
			std::ofstream jsFileStream;
#if (defined _WINDOWS) || (defined WIN32)
			jsFileStream.open(CA2W(lpszFile), ios::out);
#endif
#ifdef __linux__
			chmod(lpszFile, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			jsFileStream.open(strFileBak.c_str(), ios::out | ios::trunc);
#endif
#ifdef __APPLE__		
			jsFileStream.open(lpszFile, ios::out);
#endif
			jsFileStream.write(strBuff.c_str(),strBuff.size());
			jsFileStream.flush();
			jsFileStream.close();
#ifdef __linux__
			if (0 != ::rename(strFileBak.c_str(), lpszFile)) {
				return false;
			}
#endif
			return true;
		}
		catch(...) { return false;}
	}

#if (defined _WINDOWS) || (defined WIN32)
	//nProt: 指定共享方式 _SH_DENYNO（共享） _SH_DENYRW（独享）
	static bool WriteJsonToFileEx(const char* lpszFile, const Json::Value &jvRoot, int nProt=_SH_DENYNO)
	{
		if (!lpszFile || strlen(lpszFile) <= 0)
			return false;

		try
		{
			Json::StyledWriter jsWriter;
			std::string strBuff = jsWriter.write(jvRoot);
			std::ofstream jsFileStream;
			jsFileStream.open(CA2W(lpszFile), ios::out, nProt);
			if (!jsFileStream) return false;
			jsFileStream.write(strBuff.c_str(), strBuff.size());
			jsFileStream.flush();
			jsFileStream.close();
			return true;
		}
		catch (...) { return false; }
	}
#endif

	static bool WriteJsonToString(const Json::Value &jvRoot,std::string& strJson)
	{
		try
		{
			Json::StyledWriter writer;
			strJson = writer.write(jvRoot);
			return true;
		}
		catch(...) { return false;}
	}

	static int GetJsonValueInt(const char* lpKey,const Json::Value& jvRoot,int nDefault = 0)
	{
		try
		{
			if(jvRoot.isNull() || !jvRoot.isObject())		return nDefault;
			if(lpKey == NULL || (!jvRoot.isMember(lpKey)))	return nDefault;
			if(!jvRoot[lpKey].isInt())	return nDefault;
			return jvRoot[lpKey].asInt();
		}
		catch(...) { return nDefault;}
	}

	static string GetJsonValueString(const char* lpKey,const Json::Value& jvRoot,const char* lpszDefault = "")
	{
		string strValue = lpszDefault ? lpszDefault : "";
		try
		{
			if(jvRoot.isNull() || !jvRoot.isObject())		return strValue;
			if(lpKey == NULL || (!jvRoot.isMember(lpKey)))	return strValue;
			if(!jvRoot[lpKey].isString())	return strValue;
			return jvRoot[lpKey].asCString();
		}
		catch(...) { return strValue;}
	}
	
	static bool GetJsonValueObject(const char* lpKey,const Json::Value &jvParent,Json::Value& jvObject)
	{
		try
		{
			if(jvParent.isNull() || !jvParent.isObject())		return false;
			if(lpKey == NULL || (!jvParent.isMember(lpKey)))	return false;
			if(!jvParent[lpKey].isObject())	return false;
			jvObject = jvParent[lpKey];
			return true;
		}
		catch(...) { return false;}
	}

	static bool GetJsonValueArray(const char* lpKey,const Json::Value& jvRoot,Json::Value& jvArray)
	{
		try
		{
			if(jvRoot.isNull() || !jvRoot.isObject())		return false;
			if(lpKey == NULL || (!jvRoot.isMember(lpKey)))	return false;
			if(!jvRoot[lpKey].isArray())	return false;
			jvArray = jvRoot[lpKey];
			return true;
		}
		catch(...) { return false;}
	}

	static bool WriteJsonValueInt(const char* lpKey, Json::Value& jvRoot,int nValue)
	{
		try
		{
			if(lpKey == NULL || strlen(lpKey) <= 0)	return false;
			jvRoot[lpKey] = nValue;
			return true;
		}
		catch(...) { return false;}
	}

	static bool WriteJsonValueString(const char* lpKey, Json::Value& jvRoot, const char* lpValue)
	{
		try
		{
			if(lpKey == NULL || strlen(lpKey) <= 0)	return false;
			jvRoot[lpKey] = lpValue;
			return true;
		}
		catch(...) { return false;}
	}
};

#endif
