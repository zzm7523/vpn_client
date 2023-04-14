#ifndef __X509_CERTIFICATE_UTIL_H__
#define __X509_CERTIFICATE_UTIL_H__

#include "../config/config.h"
#include "common.h"

#include <QDateTime>
#include <QString>
#include <QByteArray>
#include <QList>
#include <QMap>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>

class X509CertificateUtil
{
public:
	static QMap<X509*, QString> load_from_pkcs12_path(const QString& path, const QByteArray& passphrase);
	static X509* load_from_pkcs12_file(const QString& file_name, const QByteArray& passphrase);

	static QMap<X509*, QString> load_from_file(const QString& file_name);
	static QList<X509*> load_from_memory(const QByteArray& memory);

#ifdef ENABLE_GUOMI
	static QMap<X509*, QString> load_from_encrypt_device(const QString& lib_path, const QString& provider_name);
#endif

#ifdef _WIN32
	static QMap<X509*, QString> load_from_mscapi(const QString& store_location);
#endif

	static QString get_user_name(X509 *cert, const QString& x509_username_field = QLatin1String("CN"));

	static QString get_friendly_name(X509 *cert);
	static QString get_issuer_friendly_name(X509 *cert);

	static QString get_common_name(X509 *cert);
	static QString get_issuer_common_name(X509 *cert);

	static QDateTime get_not_before(X509 *cert);
	static QDateTime get_not_after(X509 *cert);

	static int get_sig_alg_nid(X509 *cert);
	static QString get_sig_alg_name(X509 *cert);
	static QString get_serial_number(X509 *cert);

	static QString get_md5_fingerprint(X509 *cert, bool long_form = false);
	static QString get_sha1_fingerprint(X509 *cert, bool long_form = false);
	static QString get_sha256_fingerprint(X509 *cert, bool long_form = false);

#ifdef ENABLE_GUOMI
	static QString get_sm3_fingerprint(X509 *cert, bool long_form = false);
#endif

	static bool is_tls_server(X509 *cert);
	static bool is_tls_client(X509 *cert);
	static bool is_ca(X509 *cert);

#ifdef _WIN32
	static bool add_trusted_ca_to_system(X509 *cert);
#endif
	static bool add_cert_to_file(const QString& certFileName, X509 *cert);
	static bool add_cert_to_file(const QString& certFileName, const QList<X509*>& certs);
	static bool remove_cert_from_file(const QString& certFileName, X509 *cert);

	static QString encode_to_base64(X509 *cert);
	static X509* decode_from_base64(const QString& base64);

	static bool contains(const QMap<X509*, QString>& x509_map, X509 *cert);
	static bool contains(const QList<X509*>& cert_list, X509 *cert);

	static void free_all_cert(const QMap<X509*, QString>& x509_map);
	static void free_all_cert(QMap<int, X509*>& x509_map);
	static void free_all_cert(const QList<X509*>& cert_list);

private:
	X509CertificateUtil();

	static QString get_fingerprint(X509 *cert, const EVP_MD *digest, bool long_form = false);
	static void strncpynt(char *dest, size_t dest_len, const char *src, size_t src_len);
	static bool extract_x509_extension(X509 *cert, char *fieldname, char *out, int size);
	static bool extract_x509_field_ssl(X509_NAME *x509, const char *field_name, char *out, int size);
	static QDateTime get_time_from_asn1(const ASN1_TIME *a_time);

};

#endif
