#ifndef MY_WINPORT_H
#define MY_WINPORT_H


#include <ctype.h>
#include <limits.h>
#include <unistd.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#ifndef STDMETHOD
#define STDMETHOD(method) virtual HRESULT method
#endif

#ifndef STDMETHOD_
#define STDMETHOD_(type,method) virtual type method
#endif

#define _stricmp strcasecmp
#define ZeroMemory(dst, size) memset(dst, 0, size)
#define StringCbCopy(dst, maxsize, src) strcpy(dst, src)
#define _T(s) s

// gcc warning: unused-variable
#define UNREFERENCED_PARAMETER(P)			{ (P) = (P); }
#define DBG_UNREFERENCED_PARAMETER(P)		UNREFERENCED_PARAMETER(P)
#define DBG_UNREFERENCED_LOCAL_VARIABLE(V)	UNREFERENCED_PARAMETER(V)

#ifdef MY_DEBUG
#define Debug_View printf
#else
#define Debug_View sizeof
#endif

#ifndef MAX
#define MAX(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a,b)            (((a) < (b)) ? (a) : (b))
#endif


typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef signed long long    INT64, *PINT64;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;
typedef unsigned long long  UINT64, *PUINT64;

#if defined(__x86_64__) || defined(__aarch64__) || defined(__mips__)
	typedef INT64     INT_PTR, *PINT_PTR;
	typedef UINT64    UINT_PTR, *PUINT_PTR;
	typedef INT64     LONG_PTR, *PLONG_PTR;
	typedef UINT64    ULONG_PTR, *PULONG_PTR;
#else
	typedef int            INT_PTR;
	typedef unsigned int   UINT_PTR;
	typedef long           LONG_PTR;
	typedef unsigned long  ULONG_PTR;
#endif

typedef ULONG_PTR DWORD_PTR, *PDWORD_PTR;


#if defined(__x86_64__) || defined(__aarch64__) || defined(__mips__)
	typedef int LONG;
	typedef unsigned int ULONG;
	typedef unsigned int DWORD;
#else
	typedef long LONG;
	typedef unsigned long ULONG;
	typedef unsigned long DWORD;
#endif

typedef LONG *PLONG; 
typedef ULONG *PULONG;
typedef DWORD *PDWORD, *LPDWORD;
typedef signed short SHORT;
typedef unsigned short USHORT;
typedef SHORT *PSHORT;  
typedef USHORT *PUSHORT;
typedef unsigned char UCHAR;
typedef UCHAR *PUCHAR;
// 
#define MAX_PATH          PATH_MAX
//
#ifndef NULL
	#ifdef __cplusplus
		#define NULL    0
	#else
		#define NULL    ((void*)0)
	#endif
#endif
// 
#ifndef FALSE
	#define FALSE               0
#endif
//
#ifndef TRUE
	#define TRUE                1
#endif
//
#ifndef IN
	#define IN
#endif
//
#ifndef OUT
	#define OUT
#endif
//
#ifndef OPTIONAL
	#define OPTIONAL
#endif
//
#define WINAPI					__stdcall
#define APIENTRY    WINAPI
//
#ifndef CONST
	#define CONST               const
#endif
//
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned long long	QWORD;
typedef BOOL				*PBOOL;
typedef BOOL				*LPBOOL;
typedef BYTE				*PBYTE;
typedef BYTE				*LPBYTE;
typedef const BYTE			*LPCBYTE;
typedef WORD				*PWORD;
typedef WORD				*LPWORD;
typedef QWORD				*PQWORD;
typedef QWORD				*LPQWORD;
//
typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int        *PUINT;
//
#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))
#define LOWORD(l)           ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l)           ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define LOBYTE(w)           ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#define HIBYTE(w)           ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))


// Basics
#ifndef VOID
	#define VOID void
#endif
typedef char CHAR;
typedef CHAR TCHAR;
typedef float FLOAT;
typedef double DOUBLE;
typedef LONG SCODE;
typedef short VARIANT_BOOL;
typedef int INT;
typedef unsigned int UINT;
typedef size_t SIZE_T;
// Pointer to Basics
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
// UNICODE Types
typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR;
typedef WCHAR *PWSTR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *PCWSTR;
typedef const WCHAR *LPCWSTR;
// ANSI Types
typedef CHAR *PCHAR;
typedef CHAR *PSTR;
typedef CHAR *LPSTR;
typedef const CHAR *PCSTR;
typedef const CHAR *LPCSTR;
// TCHAR types
typedef const CHAR * LPCTSTR;
// HANDLE 
typedef void *HANDLE;
typedef HANDLE * LPHANDLE;
// HMODULE
typedef void *HMODULE;
// LONGLONG Types
typedef long long int LONGLONG;
typedef unsigned long long int ULONGLONG;
typedef LONGLONG *PLONGLONG;
typedef ULONGLONG *PULONGLONG;
typedef union _LARGE_INTEGER {
	struct {
		DWORD LowPart;
		LONG HighPart;
	};
	struct {
		DWORD LowPart;
		LONG HighPart;
	} u;
	LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
typedef union _ULARGE_INTEGER {
	struct {
		DWORD LowPart;
		DWORD HighPart;
	};
	struct {
		DWORD LowPart;
		DWORD HighPart;
	} u;
	ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;
// COM Defines and Macros
//typedef LONG HRESULT;
#ifndef HRESULT
#define HRESULT int
#endif
// 
#ifdef __cplusplus
#ifndef EXTERN_C
#define EXTERN_C    extern "C"
#endif
#else
#ifndef EXTER_C
#define EXTERN_C    extern
#endif
#endif
//

#define __forceinline
#define __fastcall

#ifndef INLINE
#ifdef __cplusplus
#define INLINE    inline
#else
#define INLINE
#endif
#endif // INLINE
//
#define DLLEXPORT		
#define DLLIMPORT 
//
#define __cdecl
#define __stdcall
#define _stdcall  
#define STDMETHODCALLTYPE       __stdcall
#define STDMETHODVCALLTYPE      __cdecl

#define STDAPICALLTYPE          __stdcall
#define STDAPIVCALLTYPE         __cdecl

#define STDAPI                  EXTERN_C HRESULT STDAPICALLTYPE
#define STDAPI_(type)           EXTERN_C type STDAPICALLTYPE

#define STDMETHODIMP            HRESULT STDMETHODCALLTYPE
#define STDMETHODIMP_(type)     type STDMETHODCALLTYPE

#define STDAPIV                 EXTERN_C HRESULT STDAPIVCALLTYPE
#define STDAPIV_(type)          EXTERN_C type STDAPIVCALLTYPE

#define STDMETHODIMPV           HRESULT STDMETHODVCALLTYPE
#define STDMETHODIMPV_(type)    type STDMETHODVCALLTYPE

//
#define CALLBACK    __stdcall

typedef int (CALLBACK *FARPROC)();


////
//#define GENERIC_READ			(0x80000000L)
//#define GENERIC_WRITE			(0x40000000L)
//#define GENERIC_EXECUTE			(0x20000000L)
//#define GENERIC_ALL				(0x10000000L)
////
//#define FILE_SHARE_READ                 0x00000001  
//#define FILE_SHARE_WRITE                0x00000002  
//#define FILE_SHARE_DELETE               0x00000004  
//#define FILE_ATTRIBUTE_READONLY				0x00000001  
//#define FILE_ATTRIBUTE_HIDDEN				0x00000002  
//#define FILE_ATTRIBUTE_SYSTEM				0x00000004  
//#define FILE_ATTRIBUTE_DIRECTORY			0x00000010  
//#define FILE_ATTRIBUTE_ARCHIVE				0x00000020  
//#define FILE_ATTRIBUTE_DEVICE				0x00000040  
//#define FILE_ATTRIBUTE_NORMAL				0x00000080  
//#define FILE_ATTRIBUTE_TEMPORARY			0x00000100  
//#define FILE_ATTRIBUTE_SPARSE_FILE			0x00000200  
//#define FILE_ATTRIBUTE_REPARSE_POINT		0x00000400  
//#define FILE_ATTRIBUTE_COMPRESSED			0x00000800  
//#define FILE_ATTRIBUTE_OFFLINE				0x00001000  
//#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000  
//#define FILE_ATTRIBUTE_ENCRYPTED			0x00004000  
//
//#define INVALID_HANDLE_VALUE		(HANDLE)-1
//#define INVALID_FILE_ATTRIBUTES		(ULONG)-1
//#define INVALID_FILE_SIZE			(ULONG)-1
//#define INVALID_SET_FILE_POINTER	(ULONG)-1

typedef struct _GUID {
	ULONG  Data1;
	USHORT Data2;
	USHORT Data3;
	UCHAR  Data4[ 8 ];
} GUID, CLSID, IID, *LPCLSID;

typedef const GUID *LPCGUID;

#ifdef __cplusplus
	#define REFGUID const GUID &
	#define REFIID const IID &
	#define REFCLSID const IID &
#else
	#define REFGUID const GUID *
	#define REFIID const IID *
	#define REFCLSID const IID *
#endif

//// Success codes
//#define S_OK                                   ((HRESULT)0x00000000L)
//#define S_FALSE                                ((HRESULT)0x00000001L)
//
//
//#define ERROR_FILE_NOT_FOUND             2L
//#define ERROR_PATH_NOT_FOUND             3L
//#define ERROR_ACCESS_DENIED              5L
//#define ERROR_INVALID_HANDLE             6L
//#define ERROR_BAD_FORMAT                 11L
//#define ERROR_SEEK                       25L
//#define ERROR_ALREADY_EXISTS             183L
//#define ERROR_NOACCESS                   998L
//#define ERROR_INVALID_USER_BUFFER        1784L
//#define ERROR_NOT_FOUND					 1168L 
//
//#define _HRESULT_TYPEDEF_(_sc) ((HRESULT)_sc)
//
//#define E_UNEXPECTED                     _HRESULT_TYPEDEF_(0x8000FFFFL)
//#define E_NOTIMPL                        _HRESULT_TYPEDEF_(0x80004001L)
//#define E_OUTOFMEMORY                    _HRESULT_TYPEDEF_(0x8007000EL)
//#define E_INVALIDARG                     _HRESULT_TYPEDEF_(0x80070057L)
//#define E_NOINTERFACE                    _HRESULT_TYPEDEF_(0x80004002L)
//#define E_POINTER                        _HRESULT_TYPEDEF_(0x80004003L)
//#define E_HANDLE                         _HRESULT_TYPEDEF_(0x80070006L)
//#define E_ABORT                          _HRESULT_TYPEDEF_(0x80004004L)
//#define E_FAIL                           _HRESULT_TYPEDEF_(0x80004005L)
//#define E_ACCESSDENIED                   _HRESULT_TYPEDEF_(0x80070005L)
//
//#define ENUM_E_LAST         0x800401BFL
//
//
//#define STG_E_UNIMPLEMENTEDFUNCTION      _HRESULT_TYPEDEF_(0x800300FEL)
//
//#define MK_S_MONIKERALREADYREGISTERED    _HRESULT_TYPEDEF_(0x000401E7L)
//
////
//// Generic test for success on any status value (non-negative numbers
//// indicate success).
////
//#define SUCCEEDED(hr) ((HRESULT)(hr) >= 0)
//#define FAILED(hr) ((HRESULT)(hr) < 0)
//
////
//// Map a WIN32 error value into a HRESULT
//// Note: This assumes that WIN32 errors fall in the range -32k to 32k.
////
//// Define bits here so macros are guaranteed to work
//
//#define FACILITY_WIN32                   7
//
//#define __HRESULT_FROM_WIN32(x) ((HRESULT)(x) <= 0 ? ((HRESULT)(x)) : ((HRESULT) (((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000)))
//#define HRESULT_FROM_WIN32(x) __HRESULT_FROM_WIN32(x)
//
//#define HRESULT_FROM_SYSCALL(x) (x) ? S_OK : HRESULT_FROM_WIN32(::GetLastError())
//
//
struct IStream;
//
//
////////////////////////////////////////////////////////////////////////////
//// crt/api:
//
//#ifndef RASSERT
//	#define RASSERT(x, _h_r_)	{ if(!(x)) return _h_r_; }
//#endif
//
//
//#include <fcntl.h>
//#include <string.h>
//#include <wchar.h>
//#include <time.h>
//
//
//#define _stricmp strcasecmp
//#define _wcsicmp wcscasecmp
//#define _strnicmp strncasecmp
//#define _snprintf snprintf
//#define _snwprintf swprintf
//
//
//inline DWORD GetFileAttributesA(LPCSTR lpFileName)
//{
//	RASSERT(lpFileName && *lpFileName, INVALID_FILE_ATTRIBUTES);
//	struct stat st;
//	RASSERT(-1 != lstat(lpFileName, &st), INVALID_FILE_ATTRIBUTES);
//	if(S_ISLNK(st.st_mode))
//	{
////		return FILE_ATTRIBUTE_ARCHIVE;
//	}
//	else if(S_ISREG(st.st_mode))
//	{
//		return FILE_ATTRIBUTE_ARCHIVE;
//	}
//	else if(S_ISDIR(st.st_mode))
//	{
//		return FILE_ATTRIBUTE_DIRECTORY;
//	}
//	return INVALID_FILE_ATTRIBUTES;
//}
//
//
//inline DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
//{
//	RASSERT(!hModule, 0);
//
//	char szBuf[PATH_MAX+1];  
//	int nCount = readlink("/proc/self/exe", szBuf, PATH_MAX);  
//	RASSERT(nCount > 0 && nCount < PATH_MAX, 0);  
//
//	RASSERT(lpFilename && nSize, nCount);
//
//	if((nSize = MIN((nSize-1), DWORD(nCount))))
//	{
//		memcpy(lpFilename, szBuf, nSize);
//		lpFilename[nSize] = 0;
//	}
//	return nSize;  
//}
//
//
//inline DWORD GetTickCount()
//{
//	struct timespec ts;
//	clock_gettime(CLOCK_MONOTONIC, &ts);
//	return (ts.tv_sec*1000 + ts.tv_nsec/1000000);
//}

struct IClientUnknown
{

    virtual HRESULT QueryInterface(char* riid, void  **ppvObject) = 0;

    virtual ULONG AddRef( void) = 0;

   	virtual ULONG Release( void) = 0;
};

#endif
