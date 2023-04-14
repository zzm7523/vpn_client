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

#define PROPERTY_MAX_LEN	256	// �����ֶ���󳤶�

typedef struct _T_DEVICE_PROPERTY
{
	TCHAR szProperty[PROPERTY_MAX_LEN];
} T_DEVICE_PROPERTY;

typedef struct _T_WQL_QUERY
{
	const CHAR  *szSelect;       // SELECT���
	const WCHAR *szProperty;     // �����ֶ�
} T_WQL_QUERY;
  
// WQL��ѯ���
static const T_WQL_QUERY szWQLQuery[] = {
	// ����ԭ��MAC��ַ
	"SELECT * FROM Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (PNPDeviceID LIKE 'PCI\\\\%')",
	L"PNPDeviceID",

	// �������к�
	"SELECT * FROM Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)",
	L"SerialNumber",

	// BIOS���к�
	"SELECT * FROM Win32_BIOS WHERE (SerialNumber IS NOT NULL)",
	L"SerialNumber",
}; 

// ͨ��PNPDeviceID��ȡ����ԭ��MAC��ַ
static BOOL WMI_DoWithPNPDeviceID( const TCHAR *PNPDeviceID, TCHAR *MacAddress, UINT uSize )
{
	TCHAR   DevicePath[MAX_PATH];
	HANDLE  hDeviceFile;
	BOOL    isOK = FALSE;

	// �����豸·����
//	StringCchCopy( DevicePath, MAX_PATH, TEXT("////.//") );
	StringCchCopy( DevicePath, MAX_PATH, TEXT("\\\\?\\") );

	StringCchCat( DevicePath, MAX_PATH, PNPDeviceID );
	StringCchCat( DevicePath, MAX_PATH, TEXT("#{ad498944-762f-11d0-8dcb-00c04fc3358c}") );

	// ��PNPDeviceID�е�/�滻��#���Ի���������豸·����
	std::replace( DevicePath + 4, DevicePath + 4 + _tcslen(PNPDeviceID), TEXT('\\'), TEXT('#') );

	// ��ȡ�豸���
	hDeviceFile = CreateFile( DevicePath, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if ( hDeviceFile != INVALID_HANDLE_VALUE ) {
		ULONG   dwID;
		BYTE    ucData[8];
		DWORD   dwByteRet;

		// ��ȡ����ԭ��MAC��ַ
		dwID = OID_802_3_PERMANENT_ADDRESS;
		isOK = DeviceIoControl(
			hDeviceFile, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwID, sizeof(dwID), ucData, sizeof(ucData), &dwByteRet, NULL );
		if ( isOK ) {
			// ���ֽ�����ת����16�����ַ���
			for( DWORD i = 0; i < dwByteRet; i++ )
				StringCchPrintf( MacAddress + (i << 1), uSize - (i << 1), TEXT("%02X"), ucData[i] );
			MacAddress[dwByteRet << 1] = TEXT('\0');  // д���ַ����������
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
	case 0:	// ����ԭ��MAC��ַ
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

	// �жϲ�ѯ�����Ƿ�֧��
	if ( (iQueryType < 0) || (iQueryType >= sizeof(szWQLQuery) / sizeof(T_WQL_QUERY)) )
		return -1;  // ��ѯ���Ͳ�֧��

	// ���WMI����COM�ӿ�   
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

	// ͨ�����ӽӿ�����WMI���ں˶�����"ROOT//CIMV2"
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

	// �����������İ�ȫ����
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

	// ͨ�������������WMI��������   
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

	// ѭ��ö�����еĽ������
	while ( pEnumerator ) {
		IWbemClassObject *pclsObj = NULL;
		ULONG uReturn = 0;

		if ( (properties != NULL) && (iTotal >= iSize) )
			break;

		pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);   
		if ( uReturn == 0 )
			break;   

		if ( properties != NULL ) {	// ��ȡ����ֵ
			VARIANT vtProperty;

			VariantInit( &vtProperty );
			pclsObj->Get( szWQLQuery[iQueryType].szProperty, 0, &vtProperty, NULL, NULL );
			StringCchCopy( properties[iTotal].szProperty, PROPERTY_MAX_LEN, W2T(vtProperty.bstrVal) );
			VariantClear( &vtProperty );

			// ������ֵ����һ���Ĵ���
			if ( WMI_DoWithProperty( iQueryType, properties[iTotal].szProperty, PROPERTY_MAX_LEN ) )   
				iTotal++;   
		} else
			iTotal++;

		pclsObj->Release();
	}

	// �ͷ���Դ
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

// !! ͨ��WMI�ӿڻ�ȡӲ����Ϣ�ٶȽ��� !!

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
		//1���������к�
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
		//2��BIOS���к�
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
		//0������ԭ��MAC��ַ
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
