#ifndef IASBundle_Impl_h
#define IASBundle_Impl_h

#include <map>
#include <vector>
#include <assert.h>
#include "ASDataType.h"
#include "ASBundle.h"
#include "qh_thread/locker.hpp"

class CASBundleImpl
{
public:

	struct VAL_ATOM
	{
		VAL_ATOM(int n1, int n2, void* p)
		{
			nType = n1; nLen = n2; lpData = p;
		}
		int nType;
		int nLen;
		void* lpData;
	};

	void clear()
	{
		QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
		for (std::map<std::string, VAL_ATOM>::iterator it = m_valTable.begin(); it != m_valTable.end(); ++it)
		{
			if (it->second.lpData)
				delete[](unsigned char*)(it->second.lpData);
		}
		m_valTable.clear();
	}

	void clone(IASBundleBase* pBundleCloneTo)
	{
		int nKeyLstLen = 0;
		unsigned char* lpKeyValues = _GetBundleKeyList(nKeyLstLen);
		if (!lpKeyValues || nKeyLstLen <= 0)
			return;

		char* lpszKey = (char*)lpKeyValues;
		while (nKeyLstLen > 0)
		{
			std::string strKey = lpszKey;
			nKeyLstLen -= (strKey.length() + 1);

			long lType = 0xFFFFFFFF;
			this->getValueType(strKey.c_str(), &lType);
			if (ASDataType::AS_VALTYPE_INT == lType)
				_CloneInt(strKey.c_str(), pBundleCloneTo);
			else if (ASDataType::AS_VALTYPE_ASTRING == lType)
				_CloneAString(strKey.c_str(), pBundleCloneTo);
			else if (ASDataType::AS_VALTYPE_WSTRING == lType)
				_CloneWString(strKey.c_str(), pBundleCloneTo);
			else if (ASDataType::AS_VALTYPE_BINARY == lType)
				_CloneBinary(strKey.c_str(), pBundleCloneTo);

			lpszKey += strKey.length() + 1;
		}

		if (lpKeyValues) delete[] lpKeyValues;
	}

	ASCode putInt(const char* lpKey, int nValue)
	{
		assert(lpKey && strlen(lpKey));
		if (!(lpKey && strlen(lpKey)))
			return ASErr_INVALIDARG;

		unsigned char* p = new unsigned char[sizeof(nValue)];
		int *ip = (int*)p;

		if (!p || !ip)	return ASErr_OUTOFMEMORY;

		*ip = nValue;
		QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
		std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
		if (it != m_valTable.end())
		{
			if (it->second.lpData)
				delete[](unsigned char*)(it->second.lpData);

			it->second.nType = ASDataType::AS_VALTYPE_INT;
			it->second.nLen = sizeof(int);
			it->second.lpData = ip;
		}
		else
			m_valTable.insert(std::make_pair(lpKey, VAL_ATOM(ASDataType::AS_VALTYPE_INT, sizeof(int), ip)));

		return ASErr_OK;
	}

	ASCode putAString(const char* lpKey, const char* lpValue)
	{
		assert((lpKey && strlen(lpKey) && lpValue));
		if (!(lpKey && strlen(lpKey) && lpValue))
			return ASErr_INVALIDARG;

		unsigned char* p = new unsigned char[(strlen(lpValue) + 1) * sizeof(char)];

		char *chp = (char*)p;

		if (!p || !chp)	return ASErr_OUTOFMEMORY;

		strcpy(chp, lpValue);

		QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
		std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
		if (it != m_valTable.end())
		{
			if (it->second.lpData)
				delete[](unsigned char*)(it->second.lpData);

			it->second.nType = ASDataType::AS_VALTYPE_ASTRING;
			it->second.nLen = (int)((strlen(lpValue) + 1) * sizeof(char));
			it->second.lpData = chp;
		}
		else
			m_valTable.insert(std::make_pair(lpKey, VAL_ATOM(ASDataType::AS_VALTYPE_ASTRING, (int)(strlen(lpValue) + 1) * sizeof(char), chp)));

		return ASErr_OK;
	}

	ASCode putWString(const char* lpKey, const wchar_t* lpValue)
	{
		assert(lpKey && strlen(lpKey) && lpValue);
		if (!(lpKey && strlen(lpKey) && lpValue))
			return ASErr_INVALIDARG;

		unsigned char* p = new unsigned char[(wcslen(lpValue) + 1) * sizeof(wchar_t)];

		wchar_t *wchp = (wchar_t*)p;

		if (!p || !wchp)	return ASErr_OUTOFMEMORY;

		wcscpy(wchp, lpValue);

		QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
		std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
		if (it != m_valTable.end())
		{
			if (it->second.lpData)
				delete[](unsigned char*)(it->second.lpData);

			it->second.nType = ASDataType::AS_VALTYPE_WSTRING;
			it->second.nLen = (int)((wcslen(lpValue) + 1) * sizeof(wchar_t));
			it->second.lpData = wchp;
		}
		else
			m_valTable.insert(std::make_pair(lpKey, VAL_ATOM(ASDataType::AS_VALTYPE_WSTRING, (int)(wcslen(lpValue) + 1) * sizeof(wchar_t), wchp)));

		return ASErr_OK;
	}

	ASCode putBinary(const char* lpKey, const unsigned char* lpData, int nLen)
	{
		assert(lpKey && strlen(lpKey) && lpData && nLen > 0);
		if (!(lpKey && strlen(lpKey) && lpData && nLen > 0))
			return ASErr_INVALIDARG;

		unsigned char* p = new unsigned char[nLen];
		if (!p) return ASErr_OUTOFMEMORY;
		memcpy(p, lpData, nLen);

		QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
		std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
		if (it != m_valTable.end())
		{
			if (it->second.lpData)
				delete[](unsigned char*)(it->second.lpData);

			it->second.nType = ASDataType::AS_VALTYPE_BINARY;
			it->second.nLen = nLen;
			it->second.lpData = p;
		}
		else
			m_valTable.insert(std::make_pair(lpKey, VAL_ATOM(ASDataType::AS_VALTYPE_BINARY, nLen, p)));

		return ASErr_OK;
	}

	ASCode getInt(const char* lpKey, int* pResult)
	{
		assert(lpKey && pResult && strlen(lpKey));
		if (!(lpKey && pResult && strlen(lpKey)))
			return ASErr_INVALIDARG;

		try
		{
		QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
			std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
			if (it == m_valTable.end())
				return ASErr_FAIL;

			if (!(it->second.nType == ASDataType::AS_VALTYPE_INT && it->second.nLen == sizeof(int)))
				return ASErr_FAIL;

			*pResult = *((int*)it->second.lpData);
			return ASErr_OK;
		}
		catch (...)
		{
			return ASErr_FAIL;
		}
	}

	ASCode getAString(const char* lpKey, char* lpBuffer, int* pBufLen)
	{
		assert(lpKey && strlen(lpKey) && pBufLen);
		if (!(lpKey && strlen(lpKey) && pBufLen))
			return ASErr_INVALIDARG;

		try
		{
			QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
			std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
			if (it == m_valTable.end())
				return ASErr_FAIL;

			assert(it->second.nType == ASDataType::AS_VALTYPE_ASTRING && static_cast<size_t>(it->second.nLen) == (strlen((char*)it->second.lpData) + 1) * sizeof(char));
			if (!(it->second.nType == ASDataType::AS_VALTYPE_ASTRING && static_cast<size_t>(it->second.nLen) == (strlen((char*)it->second.lpData) + 1) * sizeof(char)))
				return ASErr_FAIL;

			if (!lpBuffer || *pBufLen < it->second.nLen)
			{
				*pBufLen = it->second.nLen;
				return ASErr_INSUFFICIENT_BUFFER;
			}

			*pBufLen = it->second.nLen;
			strcpy(lpBuffer, (char*)it->second.lpData);
			return ASErr_OK;
		}
		catch (...)
		{
			return ASErr_FAIL;
		}
	}

	ASCode getWString(const char* lpKey, wchar_t* lpBuffer, int* pBufLen)
	{
		assert(lpKey && strlen(lpKey) && pBufLen);
		if (!(lpKey && strlen(lpKey) && pBufLen))
			return ASErr_INVALIDARG;

		try
		{
			QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
			std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
			if (it == m_valTable.end())
				return ASErr_FAIL;

			assert(it->second.nType == ASDataType::AS_VALTYPE_WSTRING && static_cast<size_t>(it->second.nLen) == (wcslen((wchar_t*)it->second.lpData) + 1) * sizeof(wchar_t));
			if (!(it->second.nType == ASDataType::AS_VALTYPE_WSTRING && static_cast<size_t>(it->second.nLen) == (wcslen((wchar_t*)it->second.lpData) + 1) * sizeof(wchar_t)))
				return ASErr_FAIL;

			if (!lpBuffer || *pBufLen < it->second.nLen)
			{
				*pBufLen = it->second.nLen;
				return ASErr_INSUFFICIENT_BUFFER;
			}

			*pBufLen = it->second.nLen;
			wcscpy(lpBuffer, (wchar_t*)it->second.lpData);
			return ASErr_OK;
		}
		catch (...)
		{
			return ASErr_FAIL;
		}
	}

	ASCode getBinary(const char* lpKey, unsigned char* lpBuffer, int* pBufLen)
	{
		assert(lpKey && strlen(lpKey) && pBufLen);
		if (!(lpKey && strlen(lpKey) && pBufLen))
			return ASErr_INVALIDARG;

		try
		{
			QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
			std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpKey);
			if (it == m_valTable.end())
				return ASErr_FAIL;

			assert(it->second.nType == ASDataType::AS_VALTYPE_BINARY);
			if (!(it->second.nType == ASDataType::AS_VALTYPE_BINARY))
				return ASErr_FAIL;

			if (!lpBuffer || *pBufLen < it->second.nLen)
			{
				*pBufLen = it->second.nLen;
				return ASErr_INSUFFICIENT_BUFFER;
			}

			*pBufLen = it->second.nLen;
			memmove(lpBuffer, it->second.lpData, it->second.nLen);
			return ASErr_OK;
		}
		catch (...)
		{
			return ASErr_FAIL;
		}
	}

	ASCode getKeyList(unsigned char* lpBuffer, INOUT int* pBufLen)
	{
		if (!pBufLen)	return ASErr_INVALIDARG;

		int nTotalLen = 0;
		std::vector<std::string> vecKeyLst;
		{
			QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
			for (std::map<std::string, VAL_ATOM>::iterator it = m_valTable.begin(); it != m_valTable.end(); ++it)
			{
				if (it->first.length() > 0)
				{
					vecKeyLst.push_back(it->first);
					nTotalLen += strlen(it->first.c_str());
					nTotalLen++;
				}
			}
		}

		if (!lpBuffer || *pBufLen < nTotalLen)
		{
			*pBufLen = nTotalLen;
			return ASErr_INSUFFICIENT_BUFFER;
		}

		*pBufLen = nTotalLen;
		for (size_t i = 0; i < vecKeyLst.size(); ++i)
		{
			memmove(lpBuffer, vecKeyLst[i].c_str(), vecKeyLst[i].length() + 1);
			lpBuffer += (vecKeyLst[i].length() + 1);
		}

		return ASErr_OK;
	}

	ASCode getValueType(const char* lpszKey, long* lpType)
	{
		if (!lpType || !lpszKey || strlen(lpszKey) <= 0)
			return ASErr_INVALIDARG;

		QH_THREAD::CMutexAutoLocker Lck(&m_valTableLock);
		std::map<std::string, VAL_ATOM>::iterator it = m_valTable.find(lpszKey);
		if (it != m_valTable.end())
		{
			*lpType = it->second.nType;
			return ASErr_OK;
		}

		return ASErr_FAIL;
	}

	CASBundleImpl(){}
	~CASBundleImpl() { clear(); }

protected:

	void _CloneInt(const char* lpszKey, IASBundleBase* pBundleCloneTo)
	{
		int nValue;
		if (ASErr_OK == getInt(lpszKey, &nValue))
			pBundleCloneTo->putInt(lpszKey, nValue);
	}

	void _CloneAString(const char* lpszKey, IASBundleBase* pBundleCloneTo)
	{
		int nLen = 0;
		if (ASErr_INSUFFICIENT_BUFFER == this->getAString(lpszKey, NULL, &nLen) && nLen > 0)
		{
			char* lpBuf = (char*)(new char[nLen]);
			if (!lpBuf)	return;

			if (ASErr_OK == this->getAString(lpszKey, lpBuf, &nLen))
			{
				pBundleCloneTo->putAString(lpszKey, lpBuf);
			}
			delete[] lpBuf;
		}
	}

	void _CloneWString(const char* lpszKey, IASBundleBase* pBundleCloneTo)
	{
		int nLen = 0;
		if (ASErr_INSUFFICIENT_BUFFER == this->getWString(lpszKey, NULL, &nLen) && nLen > 0)
		{
			wchar_t* lpBuf = (wchar_t*)(new char[nLen]);
			if (!lpBuf)	return;

			if (ASErr_OK == this->getWString(lpszKey, lpBuf, &nLen))
			{
				pBundleCloneTo->putWString(lpszKey, lpBuf);
			}
			delete[] lpBuf;
		}
	}

	void _CloneBinary(const char* lpszKey, IASBundleBase* pBundleCloneTo)
	{
		int nLen = 0;
		if (ASErr_INSUFFICIENT_BUFFER == this->getBinary(lpszKey, NULL, &nLen) && nLen > 0)
		{
			unsigned char*  lpBuf = (unsigned char*)(new char[nLen]);
			if (!lpBuf)	return;

			if (ASErr_OK == this->getBinary(lpszKey, lpBuf, &nLen))
			{
				pBundleCloneTo->putBinary(lpszKey, lpBuf, nLen);
			}
			delete[] lpBuf;
		}
	}

	inline unsigned char* _GetBundleKeyList(int& nDataLen)
	{
		nDataLen = 0;
		do
		{
			int nLen = 0;
			if (ASErr_INSUFFICIENT_BUFFER == getKeyList(NULL,&nLen) && nLen > 0)
			{
				unsigned char* lpBuffer = new unsigned char[nLen + 1];
				if (!lpBuffer)	break;
				memset(lpBuffer, 0, nLen + 1);

				if (ASErr_OK == getKeyList(lpBuffer, &nLen))
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


protected:
	QH_THREAD::CMutex m_valTableLock;
    std::map<std::string,VAL_ATOM> m_valTable;
};

#define ASBUNDLE_EASY_IMPLEMENT(theClass)\
public:\
	virtual void clear() { m_AttrBundle_##theClass.clear(); }\
	virtual void clone(IASBundleBase* pBundleCloneTo) { m_AttrBundle_##theClass.clone(pBundleCloneTo); }\
	virtual ASCode putInt(const char* lpKey, int nValue) { return m_AttrBundle_##theClass.putInt(lpKey, nValue); }\
	virtual ASCode putAString(const char* lpKey, const char* lpValue) { return m_AttrBundle_##theClass.putAString(lpKey, lpValue); }\
	virtual ASCode putWString(const char* lpKey, const wchar_t* lpValue) { return m_AttrBundle_##theClass.putWString(lpKey, lpValue); }\
	virtual ASCode putBinary(const char* lpKey, const unsigned char* lpData, int nLen) { return m_AttrBundle_##theClass.putBinary(lpKey, lpData, nLen); }\
	virtual ASCode getInt(const char* lpKey, int* pResult) { return m_AttrBundle_##theClass.getInt(lpKey, pResult); }\
	virtual ASCode getBinary(const char* lpKey, unsigned char*lpBuffer, int* pBufLen) { return m_AttrBundle_##theClass.getBinary(lpKey, lpBuffer, pBufLen); }\
	virtual ASCode getAString(const char* lpKey, OUT char* lpBuffer, INOUT int* pBufLen) { return m_AttrBundle_##theClass.getAString(lpKey, lpBuffer, pBufLen); }\
	virtual ASCode getWString(const char* lpKey, OUT wchar_t* lpBuffer, INOUT int* pBufLen) { return m_AttrBundle_##theClass.getWString(lpKey, lpBuffer, pBufLen); }\
	virtual ASCode getKeyList(unsigned char* lpBuffer, INOUT int* pBufLen) { return m_AttrBundle_##theClass.getKeyList(lpBuffer, pBufLen); }\
	virtual ASCode getValueType(const char* lpszKey, long* lpType) { return m_AttrBundle_##theClass.getValueType(lpszKey, lpType); }\
private:\
	CASBundleImpl m_AttrBundle_##theClass;

class CASBundle : public IASBundle
{
private:
	CASBundle():m_lRefCount(0){}
	~CASBundle(){}

ASBUNDLE_EASY_IMPLEMENT(CASBundle)

public:
	virtual ASCode	QueryInterface(const char* pszClsid, void** ppInterface) { return ASErr_NOIMPL; }
	virtual long	AddRef() { __sync_fetch_and_add(&m_lRefCount, 1); return m_lRefCount; }
	virtual long	Release() { __sync_fetch_and_sub(&m_lRefCount, 1); if (0 == m_lRefCount) delete this; return m_lRefCount; }

	static IASBundle* CreateInstance()
	{
		IASBundle* pBundle = new CASBundle;
		if(pBundle)pBundle->AddRef();
		return pBundle;
	}

private:
	volatile long m_lRefCount;
};

#endif