#include <QDebug>

#include "system_info.h"

#ifdef _WIN32
#pragma warning(disable:4995 4996)

#include <ShlObj.h>
#include <comutil.h>
#include <Wbemidl.h>
#include <tchar.h>
#include <strsafe.h>
#include <algorithm>
#include <atlconv.h>
#include <ntddndis.h>

#pragma comment (lib, "comsuppw.lib")   
#pragma comment (lib, "wbemuuid.lib")   

#define PROPERTY_MAX_LEN	256	// 属性字段最大长度

typedef struct _T_DEVICE_PROPERTY
{
	TCHAR szProperty[PROPERTY_MAX_LEN];
} T_DEVICE_PROPERTY;

typedef struct _T_WQL_QUERY
{
	const CHAR  *szSelect;       // SELECT语句
	const WCHAR *szProperty;     // 属性字段
} T_WQL_QUERY;
  
// WQL查询语句
static const T_WQL_QUERY szWQLQuery[] = {
	// 网卡原生MAC地址
	"SELECT * FROM Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (PNPDeviceID LIKE 'PCI\\\\%')",
	L"PNPDeviceID",

	// 主板序列号
	"SELECT * FROM Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)",
	L"SerialNumber",

	// BIOS序列号
	"SELECT * FROM Win32_BIOS WHERE (SerialNumber IS NOT NULL)",
	L"SerialNumber",
}; 

// 通过PNPDeviceID获取网卡原生MAC地址
static BOOL WMI_DoWithPNPDeviceID( const TCHAR *PNPDeviceID, TCHAR *MacAddress, UINT uSize )
{
	TCHAR   DevicePath[MAX_PATH];
	HANDLE  hDeviceFile;
	BOOL    isOK = FALSE;

	// 生成设备路径名
//	StringCchCopy( DevicePath, MAX_PATH, TEXT("////.//") );
	StringCchCopy( DevicePath, MAX_PATH, TEXT("\\\\?\\") );

	StringCchCat( DevicePath, MAX_PATH, PNPDeviceID );
	StringCchCat( DevicePath, MAX_PATH, TEXT("#{ad498944-762f-11d0-8dcb-00c04fc3358c}") );

	// 将PNPDeviceID中的/替换成#，以获得真正的设备路径名
	std::replace( DevicePath + 4, DevicePath + 4 + _tcslen(PNPDeviceID), TEXT('\\'), TEXT('#') );

	// 获取设备句柄
	hDeviceFile = CreateFile( DevicePath, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if ( hDeviceFile != INVALID_HANDLE_VALUE ) {
		ULONG   dwID;
		BYTE    ucData[8];
		DWORD   dwByteRet;

		// 获取网卡原生MAC地址
		dwID = OID_802_3_PERMANENT_ADDRESS;
		isOK = DeviceIoControl(
			hDeviceFile, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwID, sizeof(dwID), ucData, sizeof(ucData), &dwByteRet, NULL );
		if ( isOK ) {
			// 将字节数组转换成16进制字符串
			for( DWORD i = 0; i < dwByteRet; i++ )
				StringCchPrintf( MacAddress + (i << 1), uSize - (i << 1), TEXT("%02X"), ucData[i] );
			MacAddress[dwByteRet << 1] = TEXT('\0');  // 写入字符串结束标记
		}

		CloseHandle( hDeviceFile );
	}

	return isOK;
}

static BOOL WMI_DoWithProperty( INT iQueryType, TCHAR *szProperty, UINT uSize )
{
	BOOL isOK = TRUE;

	switch( iQueryType )
	{
	case 0:	// 网卡原生MAC地址
		isOK = WMI_DoWithPNPDeviceID( szProperty, szProperty, uSize );
		break;

	default:
		std::remove( szProperty, szProperty + _tcslen(szProperty) + 1, L' ' );
		break;
	}

	return isOK;
}

static INT WMI_DeviceQuery( INT iQueryType, T_DEVICE_PROPERTY *properties, INT iSize )
{
	INT iTotal = 0;
	HRESULT hres;

	// 判断查询类型是否支持
	if ( (iQueryType < 0) || (iQueryType >= sizeof(szWQLQuery) / sizeof(T_WQL_QUERY)) )
		return -1;  // 查询类型不支持

	// 获得WMI连接COM接口   
	IWbemLocator *pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		reinterpret_cast<LPVOID*>(&pLoc)
		);

	if ( FAILED(hres) )
		return -2;

	// 通过连接接口连接WMI的内核对象名"ROOT//CIMV2"
	IWbemServices *pSvc = NULL;

	hres = pLoc->ConnectServer(
		_bstr_t( L"ROOT\\CIMV2" ),
		NULL,
		NULL,
		NULL,
		0,
		NULL,
		NULL,
		&pSvc
		);

	// WBEM_E_ACCESS_DENIED
	if ( FAILED(hres) ) {
		pLoc->Release();    
		return -2;
	}

	// 设置请求代理的安全级别
	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
		);

	if ( FAILED(hres) ) {
		pSvc->Release();
		pLoc->Release();
		return -2;
	}

	// 通过请求代理来向WMI发送请求   
	IEnumWbemClassObject *pEnumerator = NULL;   
	hres = pSvc->ExecQuery(   
		bstr_t("WQL"),    
		bstr_t( szWQLQuery[iQueryType].szSelect ),   
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,    
		NULL,   
		&pEnumerator   
		);  

	if ( FAILED(hres) ) {   
		pSvc->Release();   
		pLoc->Release();   
		CoUninitialize();   
		return -3;   
	}   

	// 循环枚举所有的结果对象
	while ( pEnumerator ) {
		IWbemClassObject *pclsObj = NULL;
		ULONG uReturn = 0;

		if ( (properties != NULL) && (iTotal >= iSize) )
			break;

		pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);   
		if ( uReturn == 0 )
			break;   

		if ( properties != NULL ) {	// 获取属性值
			VARIANT vtProperty;

			VariantInit( &vtProperty );
			pclsObj->Get( szWQLQuery[iQueryType].szProperty, 0, &vtProperty, NULL, NULL );
			StringCchCopy( properties[iTotal].szProperty, PROPERTY_MAX_LEN, W2T(vtProperty.bstrVal) );
			VariantClear( &vtProperty );

			// 对属性值做进一步的处理
			if ( WMI_DoWithProperty( iQueryType, properties[iTotal].szProperty, PROPERTY_MAX_LEN ) )   
				iTotal++;   
		} else
			iTotal++;

		pclsObj->Release();
	}

	// 释放资源
	pEnumerator->Release();
	pSvc->Release();
	pLoc->Release();

	return iTotal;
}

static bool initialized = false;

class ComLibraryGuard
{
public:
	ComLibraryGuard();
	~ComLibraryGuard();

private:
	int dummy;

};

ComLibraryGuard::ComLibraryGuard()
	: dummy(0) 
{
	if (!initialized) {
		HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
		if (FAILED(hres))
			hres = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

		if (SUCCEEDED(hres)) {
			hres =  CoInitializeSecurity(
				NULL, 
				-1,                          // COM authentication
				NULL,                        // Authentication services
				NULL,                        // Reserved
				RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
				RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
				NULL,                        // Authentication info
				EOAC_NONE,                   // Additional capabilities 
				NULL                         // Reserved
				);

			if (SUCCEEDED(hres))
				initialized = true;
		}

		if (!initialized)
			qDebug() << "Failed to initialize.\n";
	}
}

ComLibraryGuard::~ComLibraryGuard()
{
	// Nothing to do
}

// !! 通过WMI接口获取硬件信息速度较慢 !!

#define MAX_PROPERTY_ARRAY	20

#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

QString SystemInfo::getMainboardId()
{
	static QString mainboardId;

	if (mainboardId.isEmpty()) {
#ifdef _WIN32
		ComLibraryGuard guard;
		T_DEVICE_PROPERTY properties[MAX_PROPERTY_ARRAY];
		//1：主板序列号
		int count = WMI_DeviceQuery(1, properties, sizeof(properties) / sizeof(T_DEVICE_PROPERTY));
		for (int i = 0; i < count; ++i)
			mainboardId.append(QString::fromWCharArray(properties[i].szProperty, -1));
#else
	// TODO
#endif
	}

	return mainboardId;
}

QString SystemInfo::getBiosId()
{
	static QString biosId;

	if (biosId.isEmpty()) {
#ifdef _WIN32
		ComLibraryGuard guard;
		T_DEVICE_PROPERTY properties[MAX_PROPERTY_ARRAY];
		//2：BIOS序列号
		int count = WMI_DeviceQuery(2, properties, sizeof(properties) / sizeof(T_DEVICE_PROPERTY));
		for (int i = 0; i < count; ++i)
			biosId.append(QString::fromWCharArray(properties[i].szProperty, -1));
#else
		// TODO
#endif
	}

	return biosId;
}

QStringList SystemInfo::getMacs()
{
	static QStringList macList;

	if (macList.isEmpty()) {
#ifdef _WIN32
		ComLibraryGuard guard;
		T_DEVICE_PROPERTY properties[MAX_PROPERTY_ARRAY];
		//0：网卡原生MAC地址
		int count = WMI_DeviceQuery(0, properties, sizeof(properties) / sizeof(T_DEVICE_PROPERTY));
		for (int i = 0; i < count; ++i)
			macList << QString::fromWCharArray(properties[i].szProperty, -1);
#else
		// TODO
#endif
	}

	return macList;
}

QString SystemInfo::getCurrentUser()
{
#ifdef _WIN32
	BOOL result = false;
	TCHAR buf[256];  
	DWORD len = sizeof(buf) / sizeof(TCHAR);

	result = GetUserNameW((LPWSTR) buf, (LPDWORD) &len);
	return result ? QString::fromWCharArray(buf) : QLatin1String("");
#else
	uid_t uid = getuid();
	struct passwd *pw = getpwuid(uid);
	if (pw)
		return pw->pw_name;
	return QLatin1String("unknown");
#endif
}
