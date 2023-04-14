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

// GMTLSv1.1, GMTLSv1, TLSv1.3, TLSv1.2Ҫ��֧�����ⳤ��ǩ��
#ifdef ENABLE_GUOMI
#define ADP_SSL_NOWITH_HARDWARE_CIPHER_LIST  "ALL:!aNULL:!eNULL:!SSLv2:!ECDHE-SM1-SHA1:!ECDHE-SM1-SM3:!ECC-SM1-SHA1:" \
	"!ECC-SM1-SM3:!RSA-SM1-SHA1:!RSA-SM1-SM3"
#define ADP_SSL_WITH_HARDWARE_CIPHER_LIST  "ALL:!aNULL:!eNULL:!SSLv2"
// SM1-OFB:SM1-CFB̫����
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
#define VPN_STATISTICS_INTERVAL 200		// ͳ�Ƹ��¼��(����)

#define VPN_CA_FILE         "ca.pem"
#define VPN_CONFIG_FILE     "vpn.conf"		// ͨ�������д��ݸ�vpn����
#define VPN_ADV_CONFIG_FILE "vpn_adv.conf"	// ͨ�������ļ����ݸ�vpn����
#define VPN_EDGE_FILE		"vpn.edge"
#define VPN_KEY_FILE        "ta.key"
#define VPN_LOG_FILE        "vpn.log"
// ������aux.xxx��Ϊ�ļ���, �½������ļ�ʱ��"ָ�����豸����Ч"
#define MISC_LOG_FILE       "misc.log"
#define VPN_STATUS_FILE     "status.log"
#define CREDIANTIALS_FILE   "cred.data"

#define VPN_CLIENT_SETTINGS_FILE   "vpn.ini"
#ifdef _WIN32
#define FINGERPRINT_FILE           "thumb.data"
#else
#define FINGERPRINT_FILE           ".thumb.data"
#endif

// ��Ҫ�Ķ�, ����������(��������ַ���Linuxƽ̨������, ���ܱ�"QSharedMemoryPrivate::initKey: unable to set key on lock"����)
#define SHARED_MEMORY_UNIQUE_KEY_PREFIX   "164291"

#define VPN_SERVICE      VPN_SERVICE_VER_ORIGINALFILENAME_STR
#define VPN_CLIENT       VPN_CLIENT_VER_ORIGINALFILENAME_STR
#define VPN_CLIENT_NAME  VPN_CLIENT_VER_INTERNALNAME_STR

#define VPN_SERVICE_NAME          "BigService"	// ��Ҫ�Ķ�
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

/* ���������ַ���, �����û��������� */
#define USER_CANCEL_INPUT   "-------USER-CANCEL-INPUT-------"

// �����豸������Ҫ��ϵͳע��֤��, ��ʱɨ��MY������10��(���1��ɨ��һ��)
#define MAX_SCAN_MY_STORE_NUM  10

#define MAX_AUTH_PASSWD_NUM    3

#define MAX_TRUSTED_CA_CACHE   50

/*
 * !!����Ҫ������֤�û�������
 * ���������ǸĽ���, �ͻ��˿����Զ�̽����Ƿ���Ҫ�ṩ�û�������
 * ���������ǹٷ���, �ͻ��˿���ͨ�����������Ƿ���Ҫ�ṩ�û�������
 */

#define STRONG_SECURITY_RESTRICTION	// ǿ��ȫ����; �������벻Ϊ�� ...

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
