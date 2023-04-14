#include "common.h"

#include <string>
#include <ctype.h>
#include <stdio.h>  
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <ShellAPI.h>
#endif

#ifdef _WIN32
#pragma warning(disable:4100)
#endif

bool is_hardware_tls_suite(const char *suite)
{
	return suite && strstr(suite, "SM1");
}

bool is_hardware_cipher(const char *cipher)
{
	return cipher && strstr(cipher, "SM1");
}

bool is_hardware_auth(const char *auth)
{
	(void) auth;
	// 目前所有摘要算法都采用软实现
	return false;
}

unsigned int count_bits(unsigned int a)
{
	unsigned int result;
	result = (a & 0x55) + ((a >> 1) & 0x55);
	result = (result & 0x33) + ((result >> 2) & 0x33);
	return ((result & 0x0F) + ((result >> 4) & 0x0F));
}

int count_netmask_bits(const char *dotted_quad)
{
	unsigned int result, a, b, c, d;
	/* Found a netmask...  Check if it is dotted quad */
	if (sscanf(dotted_quad, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return -1;
	result = count_bits(a);
	result += count_bits(b);
	result += count_bits(c);
	result += count_bits(d);
	return ((int) result);
}

bool requre_encrypt_cert(const char *tls_version)
{
	return tls_version && strcasecmp(tls_version, "GMTLSv1.1") == 0;
}

bool requre_any_length_sign(const char *tls_version)
{
	return tls_version && (strncasecmp(tls_version, "GMTLS", 5) == 0 || strcasecmp(tls_version, "TLSv1.2") == 0
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
		|| strcasecmp(tls_version, "TLSv1.3") == 0
#endif
		);
}

#ifdef _WIN32
// 检查系统版本是否是Vista或更高的版本  
static bool IsOsVersionVistaOrGreater()  
{  
	OSVERSIONINFOEXA    ovex;  
	CHAR  szVersionInfo[1024];  
	*szVersionInfo = '\x00';

	ovex.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);  
	if (!GetVersionExA((LPOSVERSIONINFOA) (&ovex))) {  
		fprintf(stdout, "check os version fail\n");  
		return false;  
	}

	return (ovex.dwMajorVersion > 5);
}

// 检查并根据系统版本选择打开程序方式  
int ShellExecuteExOpen(const char *appName, const char *params, const char *appPath)
{
	int result = 0;	// 0 表示成功

	if (IsOsVersionVistaOrGreater()) {
		SHELLEXECUTEINFOA sei = { sizeof(SHELLEXECUTEINFOA) };
		sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
		sei.lpVerb = "runas";
		sei.lpFile = appName;
		sei.lpParameters = params;
		sei.lpDirectory = appPath;
		sei.nShow = SW_SHOWNORMAL;

		if (!ShellExecuteExA(&sei)) {
			DWORD dwStatus = GetLastError();
			result = false;
			if (dwStatus == ERROR_CANCELLED) {
				result = 1;	// 1 表示放弃
				fprintf(stdout, "upgrade permissions are denied by the user\n");
			} else {
				result = 2;	// 2 表示错误
				if (dwStatus == ERROR_FILE_NOT_FOUND)
					fprintf(stdout, "%s file is not found\n", appName);
			}
		}
	} else {
		const std::string src("\\"), dest("\\\\");
		std::string strAppPath(appPath);
		std::string::size_type pos = 0;

		while ((pos = strAppPath.find(src, pos)) != std::string::npos) {
			strAppPath.replace(pos, src.size(), dest);
			pos += dest.size();
		}

		ShellExecuteA(NULL, "open", appName, params, strAppPath.c_str(), SW_SHOWNORMAL);
	}

	return result;
}
#endif
