//******************************************************************************
/*++
	FileName:		ASBundleStatic.h
	Author:			lcx
	Description:
		Bundle的静态绑定
		用法：

		class CxxBundle : public CASBundleStatic
		{
		public:
			BEGIN_BUNDLE_MAP(CxxBundle)
				BUNDLE_DATA(m_Name,		"name")
				BUNDLE_DATA(m_Rule,		"rule")
				BUNDLE_DATA(m_Handler,	"handler")
			END_BUNDLE_MAP()

		public:
			std::string		m_Name;
			std::string		m_Rule;
			PVOID			m_Handler;
		};
		
		1. 设置值后可直接使用
		2. 使用Parse(IASBundle*):可以设置各个成员变量的值【暂时未实现】
		3. 反射：可以枚举一个接口内部各个成员名称和值【暂时未实现】
--*/
//******************************************************************************
#ifndef __ASBundleStatic_H__
#define __ASBundleStatic_H__
//******************************************************************************
enum emBundleData
{
	emBundleData_Unknown,
	emBundleData_Int,
	emBundleData_AString,
	emBundleData_WString,
	emBundleData_Pointer,
	emBundleData_Blob,
};
//******************************************************************************
struct CBundleBlob 
{
	PVOID				Data;
	int					Length;
};
//******************************************************************************
struct CBundleDataMember
{
	emBundleData		Type;
	const char*			Name;
	ULONG				Offset;

	template<typename T>
	T*		GetObject	(PVOID Object);

	ASCode	GetInt		(PVOID Object, int* Result);
	ASCode	GetBinary	(PVOID Object, unsigned char* Data, int* Length);
	ASCode	GetAString	(PVOID Object, char* Data, int* Length);
	ASCode	GetWString	(PVOID Object, wchar_t* Data, int* Length);
};
//******************************************************************************
struct CBundleDataMemberTable 
{
	int					Count;
	CBundleDataMember*	Members;
};
//******************************************************************************
class CASBundleStatic : public IASBundle
{
public:
	virtual const CBundleDataMemberTable& GetMemberTable(void) = 0;

public:
	virtual ASCode	QueryInterface		(const char*,void**)					{ return ASErr_NOIMPL; }
	virtual long	AddRef				(void)									{ return 0; }
	virtual long	Release				(void)									{ return 0; }

public:
	virtual void	clear				(void)									{}
	virtual void	clone				(IASBundleBase*)						{}

	virtual ASCode	putInt				(const char*, int)						{ return ASErr_NOIMPL; }
	virtual ASCode	putAString			(const char*, const char*)				{ return ASErr_NOIMPL; }
	virtual ASCode	putWString			(const char*, const wchar_t*)			{ return ASErr_NOIMPL; }
	virtual ASCode	putBinary			(const char*, const unsigned char*,int)	{ return ASErr_NOIMPL; }

	virtual ASCode	getKeyList			(unsigned char*, int*)					{ return ASErr_NOIMPL; }
	virtual ASCode	getValueType		(const char*, long*)					{ return ASErr_NOIMPL; }

public:
	virtual ASCode	getInt				(const char*, int*);
	virtual ASCode	getBinary			(const char*, unsigned char*,int*);
	virtual ASCode	getAString			(const char*, char*, int*);
	virtual ASCode	getWString			(const char*, wchar_t*, int*);
};
//******************************************************************************
//
//	helper
//
//******************************************************************************
template<typename T> struct BUNDLE_TYPE;
template<> struct BUNDLE_TYPE<int>						{ static const emBundleData TYPE = emBundleData_Int; };
template<> struct BUNDLE_TYPE<std::string>				{ static const emBundleData TYPE = emBundleData_AString; };
template<> struct BUNDLE_TYPE<std::wstring>				{ static const emBundleData TYPE = emBundleData_WString; };
template<> struct BUNDLE_TYPE<PVOID>					{ static const emBundleData TYPE = emBundleData_Pointer; };
template<> struct BUNDLE_TYPE<CBundleBlob>				{ static const emBundleData TYPE = emBundleData_Blob; };
//******************************************************************************
inline const emBundleData GET_BUNDLE_TYPE(int&)			{ return emBundleData_Int; };
inline const emBundleData GET_BUNDLE_TYPE(std::string&)	{ return emBundleData_AString; };
inline const emBundleData GET_BUNDLE_TYPE(std::wstring&){ return emBundleData_WString; };
inline const emBundleData GET_BUNDLE_TYPE(PVOID&)		{ return emBundleData_Pointer; };
inline const emBundleData GET_BUNDLE_TYPE(CBundleBlob&)	{ return emBundleData_Blob; };
//******************************************************************************
#define BEGIN_BUNDLE_MAP(class)													\
		typedef class __class__;												\
		virtual const CBundleDataMemberTable& GetMemberTable(void)				\
		{																		\
			static CBundleDataMember __item__ [] = 								\
			{

#define BUNDLE_DATA(data, name)													\
			{																	\
				GET_BUNDLE_TYPE(((__class__*)0)->##data),						\
				name,															\
				(ULONG)&((__class__*)0)->##data									\
			},

#define END_BUNDLE_MAP()														\
			};																	\
			static CBundleDataMemberTable __table__ = 							\
			{																	\
				_countof(__item__),												\
				__item__														\
			};																	\
			return __table__;													\
		}
//******************************************************************************
//
//	implement
//
//******************************************************************************
template<typename T>
inline T* CBundleDataMember::GetObject(PVOID Object)
{
	return (T*)((ULONG_PTR)Object + Offset);
}
//******************************************************************************
inline ASCode CBundleDataMember::GetInt(PVOID Object, int* Result)
{
	if (Type != emBundleData_Int)
		return ASErr_FAIL;

	*Result = *(GetObject<int>(Object));

	return ASErr_OK;
}
//******************************************************************************
inline ASCode CBundleDataMember::GetBinary(PVOID Object, unsigned char* Data, int* Length)
{
	void* data = NULL;
	int data_len = 0;

	switch (Type)
	{
	case emBundleData_Blob:
		{
			CBundleBlob* blob = GetObject<CBundleBlob>(Object);
			data = blob->Data;
			data_len = blob->Length;
		}
		break;

	case emBundleData_Pointer:
		{
			PVOID* ptr = GetObject<PVOID>(Object);
			data = ptr;
			data_len = sizeof(PVOID);
		}
		break;

	default:
		return ASErr_FAIL;
	}

	if (!Data || *Length < data_len)
	{
		*Length = data_len;
		return ASErr_INSUFFICIENT_BUFFER;
	}

	memcpy(Data, data, *Length);
	*Length = data_len;

	return ASErr_OK;
}
//******************************************************************************
inline ASCode CBundleDataMember::GetAString(PVOID Object, char* Data, int* Length)
{
	const char* data = NULL;
	int data_len = 0;

	switch (Type)
	{
	case emBundleData_AString:
		{
			std::string* str = GetObject<std::string>(Object);
			data = str->data();
			data_len = str->length() + 1;
		}
		break;

	default:
		return ASErr_FAIL;
	}

	if (!Data || *Length < data_len)
	{
		*Length = data_len;
		return ASErr_INSUFFICIENT_BUFFER;
	}

	strncpy(Data, data, *Length);
	*Length = data_len;

	return ASErr_OK;
}
//******************************************************************************
inline ASCode CBundleDataMember::GetWString(PVOID Object, wchar_t* Data, int* Length)
{
	const wchar_t* data = NULL;
	int data_len = 0;

	switch (Type)
	{
	case emBundleData_WString:
		{
			std::wstring* str = GetObject<std::wstring>(Object);
			data = str->data();
			data_len = str->length() + 1;
		}
		break;

	default:
		return ASErr_FAIL;
	}

	if (!Data || *Length < data_len)
	{
		*Length = data_len;
		return ASErr_INSUFFICIENT_BUFFER;
	}

	wcsncpy(Data, data, *Length);
	*Length = data_len;

	return ASErr_OK;
}
//******************************************************************************
inline ASCode CASBundleStatic::getInt(const char* Name, int* Result)
{
	if (!Name || !Name[0] || !Result)
		return ASErr_INVALIDARG;

	const CBundleDataMemberTable& members = GetMemberTable();

	for (int i = 0; i < members.Count; i++)
	{
		if (0 == strcmp(Name, members.Members[i].Name))
			return members.Members[i].GetInt(this, Result);
	}

	return ASErr_FAIL;
}
//******************************************************************************
inline ASCode CASBundleStatic::getBinary(const char* Name, unsigned char* Data,int* Length)
{
	if (!Name || !Name[0] || !Length)
		return ASErr_INVALIDARG;

	const CBundleDataMemberTable& members = GetMemberTable();

	for (int i = 0; i < members.Count; i++)
	{
		if (0 == strcmp(Name, members.Members[i].Name))
			return members.Members[i].GetBinary(this, Data, Length);
	}

	return ASErr_FAIL;
}
//******************************************************************************
inline ASCode CASBundleStatic::getAString(const char* Name, char* Data, int* Length)
{
	if (!Name || !Name[0] || !Length)
		return ASErr_INVALIDARG;

	const CBundleDataMemberTable& members = GetMemberTable();

	for (int i = 0; i < members.Count; i++)
	{
		if (0 == strcmp(Name, members.Members[i].Name))
			return members.Members[i].GetAString(this, Data, Length);
	}

	return ASErr_FAIL;
}
//******************************************************************************
inline ASCode CASBundleStatic::getWString(const char* Name, wchar_t* Data, int* Length)
{
	if (!Name || !Name[0] || !Length)
		return ASErr_INVALIDARG;

	const CBundleDataMemberTable& members = GetMemberTable();

	for (int i = 0; i < members.Count; i++)
	{
		if (0 == strcmp(Name, members.Members[i].Name))
			return members.Members[i].GetWString(this, Data, Length);
	}

	return ASErr_FAIL;
}
//******************************************************************************
#endif
