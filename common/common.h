#ifndef __COMMON_H__
#define __COMMON_H__

#include "../config/config.h"
#include "../config/version.h"

#include <string.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <openssl/opensslv.h>

#ifdef __cplusplus
extern "C" {
#endif

// GMTLSv1.1, GMTLSv1, TLSv1.3, TLSv1.2要求支持任意长度签名
#ifdef ENABLE_GUOMI
#define ADP_SSL_NOWITH_HARDWARE_CIPHER_LIST  "ALL:!aNULL:!eNULL:!SSLv2:!ECDHE-SM1-SHA1:!ECDHE-SM1-SM3:!ECC-SM1-SHA1:" \
	"!ECC-SM1-SM3:!RSA-SM1-SHA1:!RSA-SM1-SM3"
#define ADP_SSL_WITH_HARDWARE_CIPHER_LIST  "ALL:!aNULL:!eNULL:!SSLv2"
// SM1-OFB:SM1-CFB太慢了
#define CHANNEL_HARDWARE_CIPHER_LIST   "SM1-CBC"
#define CHANNEL_SOFTWARE_CIPHER_LIST   "SM4-CBC:SM4-OFB:SM4-CFB:AES-256-CBC:AES-256-OFB:AES-256-CFB:AES-192-CBC:" \
	"AES-192-OFB:AES-192-CFB:AES-128-CBC:AES-128-OFB:AES-128-CFB:BF-CBC:BF-OFB:BF-CFB:DES-EDE3-CBC:DES-EDE3-OFB:DES-EDE3-CFB"
#define CHANNEL_AUTH_LIST   "SM3:SHA256:SHA1:MD5"
#define TLS_VERSION_LIST    "GMTLSv1.1:GMTLSv1:TLSv1.2:TLSv1.1:TLSv1"
#else
#define ADP_SSL_NOWITH_HARDWARE_CIPHER_LIST  "ALL:!aNULL:!eNULL:!SSLv2"
#define CHANNEL_SOFTWARE_CIPHER_LIST  "AES-256-CBC:AES-256-OFB:AES-256-CFB:AES-192-CBC:AES-192-OFB:AES-192-CFB:" \
	"AES-128-CBC:AES-128-OFB:AES-128-CFB:BF-CBC:BF-OFB:BF-CFB:DES-EDE3-CBC:DES-EDE3-OFB:DES-EDE3-CFB"
#define CHANNEL_AUTH_LIST   "SHA256:SHA1:MD5"
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#define TLS_VERSION_LIST    "TLSv1.2:TLSv1.1:TLSv1"
#else
#define TLS_VERSION_LIST    "TLSv1.3:TLSv1.2:TLSv1.1:TLSv1"
#endif
#endif

#define VPN_PORT          1194
#define MIN_SALT_LEN      8
#define VPN_STATISTICS_INTERVAL 200		// 统计更新间隔(毫秒)

#define VPN_CA_FILE         "ca.pem"
#define VPN_CONFIG_FILE     "vpn.conf"		// 通过命令行传递给vpn进程
#define VPN_ADV_CONFIG_FILE "vpn_adv.conf"	// 通过配置文件传递给vpn进程
#define VPN_EDGE_FILE		"vpn.edge"
#define VPN_KEY_FILE        "ta.key"
#define VPN_LOG_FILE        "vpn.log"
// 不能用aux.xxx作为文件名, 新建这种文件时报"指定的设备名无效"
#define MISC_LOG_FILE       "misc.log"
#define VPN_STATUS_FILE     "status.log"
#define CREDIANTIALS_FILE   "cred.data"

#define VPN_CLIENT_SETTINGS_FILE   "vpn.ini"
#ifdef _WIN32
#define FINGERPRINT_FILE           "thumb.data"
#else
#define FINGERPRINT_FILE           ".thumb.data"
#endif

// 不要改动, 仅包含数字(如果包含字符在Linux平台有问题, 可能报"QSharedMemoryPrivate::initKey: unable to set key on lock"错误)
#define SHARED_MEMORY_UNIQUE_KEY_PREFIX   "164291"

#define VPN_SERVICE      VPN_SERVICE_VER_ORIGINALFILENAME_STR
#define VPN_CLIENT       VPN_CLIENT_VER_ORIGINALFILENAME_STR
#define VPN_CLIENT_NAME  VPN_CLIENT_VER_INTERNALNAME_STR

#define VPN_SERVICE_NAME          "BigService"	// 不要改动
#define VPN_SERVICE_DISPLAY_NAME  "Big SSL VPN"
#define VPN_SERVICE_DESCRIPTION   "Big SSL VPN Service"

#define VPN_CONFIG_DIR_NAME	      "Big SSL VPN"

#ifdef _WIN32
#define VPN_PROCESS         "openvpn.exe"
#define ENCRYPT_DEVICE_TOOL "encrypt_device_tool.exe"
#else
#define VPN_PROCESS         "openvpn"
#define ENCRYPT_DEVICE_TOOL "encrypt_device_tool"
#endif

#define FIX_OK_CANCEL_TR

/* 定义特殊字符串, 代表用户放弃输入 */
#define USER_CANCEL_INPUT   "-------USER-CANCEL-INPUT-------"

// 加密设备可能需要向系统注册证书, 定时扫描MY不超过10次(间隔1秒扫描一次)
#define MAX_SCAN_MY_STORE_NUM  10

#define MAX_AUTH_PASSWD_NUM    3

#define MAX_TRUSTED_CA_CACHE   50

/*
 * !!不需要总是认证用户名密码
 * 如果服务端是改进版, 客户端可以自动探测出是否需要提供用户名密码
 * 如果服务端是官方版, 客户端可以通过界面配置是否需要提供用户名密码
 */

#define STRONG_SECURITY_RESTRICTION	// 强安全限制; 例如密码不为空 ...

#ifndef __MIN__
#define __MIN__(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef __MAX__
#define __MAX__(a,b) (((a) > (b)) ? (a) : (b))
#endif

bool is_hardware_tls_suite(const char *suite);
bool is_hardware_cipher(const char *cipher);
bool is_hardware_auth(const char *auth);

unsigned int count_bits(unsigned int a);
int count_netmask_bits(const char *dotted_quad);

bool requre_encrypt_cert(const char *tls_version);
bool requre_any_length_sign(const char *tls_version);

#ifdef _WIN32
#define strncasecmp _strnicmp
#define strcasecmp _stricmp

int ShellExecuteExOpen(const char *appName, const char *params, const char *appPath);
#endif

#ifdef __cplusplus
}
#endif

#endif
