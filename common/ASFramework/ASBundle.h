//
//
//  ASBundle.h
//  android.os.bundle的一个c++实现，用途不变
//  Created by dengfan on 16/3/19.
//  Copyright © 2016年 qihoo. All rights reserved.
//

#ifndef IASBundle_h
#define IASBundle_h

#include "ASUnknown.h"
#include "ASMacros.h"

class IASBundleBase
{
public:

	virtual void clear() = 0;
	virtual void clone(IASBundleBase* pBundleCloneTo) = 0;

	virtual ASCode putInt(const char* lpKey,int nValue) = 0;
	virtual ASCode putAString(const char* lpKey,const char* lpValue) = 0;
	virtual ASCode putWString(const char* lpKey,const wchar_t* lpValue) = 0;
	virtual ASCode putBinary(const char* lpKey,const unsigned char* lpData,int nLen) = 0;

	virtual ASCode getInt(const char* lpKey,int* pResult) = 0;
	virtual ASCode getBinary(const char* lpKey,unsigned char*lpBuffer,int* pBufLen) = 0;
	virtual ASCode getAString(const char* lpKey,OUT char* lpBuffer,INOUT int* pBufLen) = 0;
	virtual ASCode getWString(const char* lpKey,OUT wchar_t* lpBuffer,INOUT int* pBufLen) = 0;

	//获取bundle内的key列表,用\0分隔,类似windows的multisz类型    
	virtual ASCode getKeyList(unsigned char* lpBuffer, INOUT int* pBufLen) = 0;
	virtual ASCode getValueType(const char* lpszKey, long* lpType) = 0;
};

class IASBundle : public IASBundleBase,public IASUnknown
{
public:
	virtual ~IASBundle() { }

public:
	inline int getASBundleInt(const char* lpKey, int nDefault = 0)
	{
		if (!this || !lpKey || !lpKey[0])
			return nDefault;

		int nResult = nDefault;

		return (ASErr_OK == getInt(lpKey,&nResult)) ? nResult : nDefault;
	}

	inline std::string getASBundleAString(const char* lpKey, const char* lpDefault = "")
	{
		std::string strRet = lpDefault ? lpDefault : "";

		if (!this || !lpKey || !lpKey[0])
			return strRet;

		do
		{
			int nLen = 0;

			if(ASErr_INSUFFICIENT_BUFFER == getAString(lpKey, NULL, &nLen) && nLen > 0)
			{
				char* lpBuf = (char*)(new char[nLen]);

				if(!lpBuf)
					break;

				if(ASErr_OK == getAString(lpKey,lpBuf,&nLen))
					strRet = lpBuf;

				delete [] lpBuf;
			}

		}while(0);

		return strRet;
	}

	inline void* getASBundlePtr(const char* lpKey)
	{
		if (!this || !lpKey || !lpKey[0])
			return NULL;

		void* ptr = NULL;
		int len = sizeof(ptr);

		getBinary(lpKey, (unsigned char*)&ptr, &len);

		return ptr;
	}
};

#define ASBUNDLE_EASY_IMPLEMENT_BY_POINTER(theClass)\
public:\
	virtual void clear() { if(m_pAttrBundle_##theClass) m_pAttrBundle_##theClass->clear(); }\
	virtual void clone(IASBundleBase* pBundleCloneTo) { if(m_pAttrBundle_##theClass) m_pAttrBundle_##theClass->clone(pBundleCloneTo); }\
	virtual ASCode putInt(const char* lpKey, int nValue) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->putInt(lpKey, nValue) : ASErr_FAIL; }\
	virtual ASCode putAString(const char* lpKey, const char* lpValue) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->putAString(lpKey, lpValue) : ASErr_FAIL; }\
	virtual ASCode putWString(const char* lpKey, const wchar_t* lpValue) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->putWString(lpKey, lpValue) : ASErr_FAIL; }\
	virtual ASCode putBinary(const char* lpKey, const unsigned char* lpData, int nLen) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->putBinary(lpKey, lpData, nLen) : ASErr_FAIL; }\
	virtual ASCode getInt(const char* lpKey, int* pResult) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->getInt(lpKey, pResult) : ASErr_FAIL; }\
	virtual ASCode getBinary(const char* lpKey, unsigned char*lpBuffer, int* pBufLen) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->getBinary(lpKey, lpBuffer, pBufLen) : ASErr_FAIL; }\
	virtual ASCode getAString(const char* lpKey, OUT char* lpBuffer, INOUT int* pBufLen) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->getAString(lpKey, lpBuffer, pBufLen) : ASErr_FAIL; }\
	virtual ASCode getWString(const char* lpKey, OUT wchar_t* lpBuffer, INOUT int* pBufLen) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->getWString(lpKey, lpBuffer, pBufLen) : ASErr_FAIL; }\
	virtual ASCode getKeyList(unsigned char* lpBuffer, INOUT int* pBufLen) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->getKeyList(lpBuffer, pBufLen) : ASErr_FAIL; }\
	virtual ASCode getValueType(const char* lpszKey, long* lpType) { return m_pAttrBundle_##theClass ? m_pAttrBundle_##theClass->getValueType(lpszKey, lpType) : ASErr_FAIL; }\
private:\
	IASBundle* m_pAttrBundle_##theClass;

namespace ASBundleHelper
{
	template<typename TASBundle>
	inline int getBundleInt(TASBundle* pBundle,const char* lpKey,int nDefault)
	{
		if(!pBundle || !lpKey)
			return nDefault;

		int nResult = nDefault;
		return (ASErr_OK == pBundle->getInt(lpKey,&nResult)) ? nResult : nDefault;
	}

	inline int getBundleInt(IASBundle* pBundle,const char* lpKey,int nDefault)
	{
		return getBundleInt<IASBundle>(pBundle, lpKey, nDefault);
	}

	//  返回的是数组指针，请用完后自行释放！
	template<typename TASBundle>
	inline unsigned char* getBundleBinary(TASBundle* pBundle,const char* lpKey,int& nDataLen)
	{
		if(!(pBundle && strlen(lpKey)))
			return NULL;

		unsigned char*  lpRet = NULL;
		do
		{
			int nLen = 0;
			if(ASErr_INSUFFICIENT_BUFFER == pBundle->getBinary(lpKey,NULL,&nLen) && nLen > 0)
			{
				unsigned char*  lpBuf = (unsigned char* )(new char[nLen]);
				if(!lpBuf)	break;

				if(ASErr_OK == pBundle->getBinary(lpKey,lpBuf,&nLen))
				{
					nDataLen = nLen;
					lpRet = lpBuf;
				}
				else
					delete [] lpBuf;
			}

		}while(0);
		return lpRet;
	}

	inline unsigned char* getBundleBinary(IASBundle* pBundle,const char* lpKey,int& nDataLen)
	{
		return getBundleBinary<IASBundle>(pBundle, lpKey, nDataLen);
	}

	inline std::string getBundleBinary4String(IASBundle* pBundle, const char* lpKey, const char* lpDefault)
	{
		std::string strDefault = lpDefault ? lpDefault : "";
		if(!(pBundle && strlen(lpKey))) return strDefault;

		int nDataLen = 0;
		char* pBuf = reinterpret_cast<char*>(getBundleBinary(pBundle, lpKey, nDataLen));
		if(!pBuf) return strDefault;

		strDefault = std::string(pBuf, nDataLen);
		delete[] pBuf;
		return strDefault;
	}

	template<typename TASBundle>
	inline std::string getBundleAString(TASBundle* pBundle,const char* lpKey,const char* lpDefault)
	{
		std::string strRet = lpDefault ? lpDefault : "";
		if(!(pBundle && strlen(lpKey)))
			return strRet;

		do
		{
			int nLen = 0;
			if(ASErr_INSUFFICIENT_BUFFER == pBundle->getAString(lpKey,NULL,&nLen) && nLen > 0)
			{
				char* lpBuf = (char*)(new char[nLen]);
				if(!lpBuf)	break;

				if(ASErr_OK == pBundle->getAString(lpKey,lpBuf,&nLen))
					strRet = lpBuf;

				delete [] lpBuf;
			}

		}while(0);
		return strRet;
	}

	inline std::string getBundleAString(IASBundle* pBundle,const char* lpKey,const char* lpDefault)
	{
		return getBundleAString<IASBundle>(pBundle, lpKey, lpDefault);
	}

	template<typename TASBundle>
	inline std::wstring getBundleWString(TASBundle* pBundle,const char* lpKey,const wchar_t* lpDefault)
	{
		std::wstring strRet = lpDefault ? lpDefault : L"";
		if(!(pBundle && strlen(lpKey)))
			return strRet;

		do
		{
			int nLen = 0;
			if(ASErr_INSUFFICIENT_BUFFER == pBundle->getWString(lpKey,NULL,&nLen) && nLen > 0)
			{
				wchar_t* lpBuf = (wchar_t*)(new char[nLen]);
				if(!lpBuf)	break;

				if(ASErr_OK == pBundle->getWString(lpKey,lpBuf,&nLen))
					strRet = lpBuf;

				delete [] lpBuf;
			}

		}while(0);
		return strRet;
	}

	inline std::wstring getBundleWString(IASBundle* pBundle,const char* lpKey,const wchar_t* lpDefault)
	{
		return getBundleWString<IASBundle>(pBundle, lpKey, lpDefault);
	}

	//  返回的是数组指针，请用完后自行释放！
	template<typename TASBundle>
	inline unsigned char* getBundleKeyList(TASBundle* pBundle,int& nDataLen)
	{
		nDataLen = 0;
		do
		{
			int nLen = 0;
			if (ASErr_INSUFFICIENT_BUFFER == pBundle->getKeyList(NULL,&nLen) && nLen > 0)
			{
				unsigned char* lpBuffer = new unsigned char[nLen + 1];
				if (!lpBuffer)	break;
				memset(lpBuffer, 0, nLen + 1);

				if (ASErr_OK == pBundle->getKeyList(lpBuffer, &nLen))
				{
					nDataLen = nLen;
					return lpBuffer;
				}
				else
				{
					delete[] lpBuffer;
				}
			}

		} while (0);

		return NULL;
	}

	inline unsigned char* getBundleKeyList(IASBundle* pBundle,int& nDataLen)
	{
		return getBundleKeyList<IASBundle>(pBundle, nDataLen);
	}
};

#endif /* IASBundle_h */
