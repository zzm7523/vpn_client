#include <QApplication>
#include <QFile>
#include <QDir>
#include <QListIterator>
#include <QMapIterator>
#include <QDebug>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <wincrypt.h>
#endif

#include "common.h"
#include "file_util.h"
#include "x509_certificate_info.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#ifdef ENABLE_GUOMI
#include <openssl/encrypt_device.h>
#endif

#include "asn1_int.h"
#include "x509_certificate_util.h"
#include "pkcs12_util.h"
#include "encrypt_device_manager.h"

QMap<X509*, QString> X509CertificateUtil::load_from_pkcs12_path(const QString& path, const QByteArray& passphrase)
{
	QMap<X509*, QString> x509_map;
	X509 *x509;

	const QDir pkcs12Dir(path);
	QListIterator<QString> z(pkcs12Dir.entryList(QDir::Files, QDir::Name));

	while (z.hasNext()) {
		const QString pkcs12File = pkcs12Dir.absoluteFilePath(z.next());
		if (pkcs12File.endsWith(QLatin1String(".p12"), Qt::CaseInsensitive)) {
			x509 = load_from_pkcs12_file(pkcs12File, passphrase);
			if (x509)
				x509_map.insert(x509, pkcs12File);
		}
		QApplication::processEvents();
	}

	return x509_map;
}

X509* X509CertificateUtil::load_from_pkcs12_file(const QString& file_name, const QByteArray& passphrase)
{
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;

	Pkcs12Util::readPkcs12(file_name, passphrase, &pkey, &x509, NULL);
	if (pkey)
		EVP_PKEY_free(pkey);

	return x509;
}

QMap<X509*, QString> X509CertificateUtil::load_from_file(const QString& file_name)
{
	QMap<X509*, QString> x509_map;
	X509 *x509;

	/*
	 * 操作系统可能采用Local8Bit字符集，也可能采用UTF-8字符集，或其它...
	 * 文件名称从QString转换成const char*时采用那个字符集不好确定
	 * 使用QFile读取证书内容到缓存(由QT做字符集处理), 使用内存BIO; 不使用文件BIO
	 */
	QFile x_file(file_name);
	if (x_file.open(QIODevice::ReadOnly)) {
		QByteArray mem = x_file.readAll();
		x_file.close();

		BIO *bio = BIO_new_mem_buf(mem.data(), mem.size());
		while (true) {
			x509 = NULL;
			if (PEM_read_bio_X509(bio, &x509, NULL, NULL))
				x509_map.insert(x509, file_name);
			else
				break;
		}
		BIO_free(bio);
	}

	return x509_map;
}

QList<X509*> X509CertificateUtil::load_from_memory(const QByteArray& memory)
{
	QList<X509*> x509_list;
	X509 *x509;

	BIO *bio = BIO_new_mem_buf((void*) memory.data(), memory.size());
	if (bio) {
		while (true) {
			x509 = NULL;
			if (PEM_read_bio_X509(bio, &x509, NULL, NULL))
				x509_list.append(x509);
			else
				break;
		}
		BIO_free(bio);
	}

	return x509_list;
}

#ifdef _WIN32
QMap<X509*, QString> X509CertificateUtil::load_from_mscapi(const QString& store_location)
{
	QMap<X509*, QString> x509_map;
	HCERTSTORE hStoreHandle = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	HCRYPTPROV crypt_prov = NULL;
	DWORD key_spec;
	BOOL free_crypt_prov;

	wchar_t wchar_array[1024];
	int actual_len = store_location.toWCharArray(wchar_array);
	wchar_array[actual_len] = 0x0;

	if ((hStoreHandle = CertOpenStore((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER |
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, wchar_array))) {
		X509 *x509 = NULL;
		BIO *bio = NULL;

		while ((pCertContext = CertEnumCertificatesInStore(hStoreHandle, pCertContext))) {
			if (CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL,
					&crypt_prov, &key_spec, &free_crypt_prov)) {
				bio = BIO_new_mem_buf(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
				if (bio) {
					if ((x509 = d2i_X509_bio(bio, NULL)))
						x509_map.insert(x509, X509CertificateUtil::get_sha1_fingerprint(x509));
					BIO_free(bio);
				}
				if (free_crypt_prov)
					CryptReleaseContext(crypt_prov, 0);
			}
		}

		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		CertCloseStore(hStoreHandle, 0);
	}

	return x509_map;
}
#endif

static void OPENSSL_STRING_free(char *str)
{
	if (str)
		OPENSSL_free(str);
}

#ifdef ENABLE_GUOMI
QMap<X509*, QString> X509CertificateUtil::load_from_encrypt_device(const QString& lib_path, const QString& provider_name)
{
	ENCRYPT_DEVICE_PROVIDER *provider;
	provider = ENCRYPT_DEVICE_PROVIDER_load(qPrintable(lib_path), qPrintable(provider_name));
	if (!provider)
		return QMap<X509*, QString>();

	STACK_OF(OPENSSL_STRING) *dev_stack = sk_OPENSSL_STRING_new_null();
	if (!ENCRYPT_DEVICE_enum(provider, dev_stack)) {
		sk_OPENSSL_STRING_pop_free(dev_stack, OPENSSL_STRING_free);
		ENCRYPT_DEVICE_PROVIDER_unload(provider);
		return QMap<X509*, QString>();
	}

	STACK_OF(OPENSSL_STRING) *con_stack = NULL;
	QMap<X509*, QString> x509_map;
	X509 *sign_cert;
	ENCRYPT_DEVICE *device;
	ENCRYPT_DEVICE_CONTAINER *container;
	char *path_name;

	for (int i = 0; i < sk_OPENSSL_STRING_num(dev_stack); ++i) {
		device = ENCRYPT_DEVICE_open(provider, sk_OPENSSL_STRING_value(dev_stack, i), 0);
		if (device) {
			con_stack = sk_OPENSSL_STRING_new_null();

			if (ENCRYPT_DEVICE_CONTAINER_enum(device, con_stack)) {
				for (int j = 0; j < sk_OPENSSL_STRING_num(con_stack); ++j) {
					path_name = sk_OPENSSL_STRING_value(con_stack, j);
					container = ENCRYPT_DEVICE_CONTAINER_open(device, path_name);

					if (container) {
						if (ENCRYPT_DEVICE_CONTAINER_read_certs(container, &sign_cert, NULL, NULL, NULL)) {
							x509_map.insert(sign_cert, path_name);
						}
						ENCRYPT_DEVICE_CONTAINER_close(container);
					}
				}
			}

			sk_OPENSSL_STRING_pop_free(con_stack, OPENSSL_STRING_free);
			ENCRYPT_DEVICE_close(device);
		}
	}

	sk_OPENSSL_STRING_pop_free(dev_stack, OPENSSL_STRING_free);
	ENCRYPT_DEVICE_PROVIDER_unload(provider);

	return x509_map;
}
#endif

QString X509CertificateUtil::get_user_name(X509 *cert, const QString& x509_username_field)
{
	bool ret = false;
	char buf[1024];
	int buf_len = 1024;

	if (x509_username_field.startsWith(QLatin1String("ext:"), Qt::CaseSensitive))
		ret = extract_x509_extension(cert, x509_username_field.toLatin1().data(), buf, buf_len);
	else
		ret = extract_x509_field_ssl(X509_get_subject_name(cert), x509_username_field.toLatin1().data(), buf, buf_len);

	return ret == 1 ? QString::fromUtf8(buf) : QLatin1String("");
}

QString
X509CertificateUtil::get_friendly_name(X509 *cert)
{
	// NID_commonName, NID_pkcs9_emailAddress, NID_organizationalUnitName, NID_organizationName;
	char buf[1024];
	int buf_len = 1024;

	int ret = extract_x509_field_ssl(X509_get_subject_name(cert), "CN", buf, buf_len);
	if (!ret)
		ret = extract_x509_field_ssl(X509_get_subject_name(cert), "Email", buf, buf_len);
	if (!ret)
		ret = extract_x509_field_ssl(X509_get_subject_name(cert), "OU", buf, buf_len);
	if (!ret)
		ret = extract_x509_field_ssl(X509_get_subject_name(cert), "O", buf, buf_len);

	return ret == 1 ? QString::fromUtf8(buf) : QLatin1String("");
}

QString X509CertificateUtil::get_issuer_friendly_name(X509 *cert)
{
	// NID_commonName, NID_pkcs9_emailAddress, NID_organizationalUnitName, NID_organizationName;
	char buf[1024];
	int buf_len = 1024;

	int ret = extract_x509_field_ssl(X509_get_issuer_name(cert), "CN", buf, buf_len);
	if (!ret)
		ret = extract_x509_field_ssl(X509_get_issuer_name(cert), "Email", buf, buf_len);
	if (!ret)
		ret = extract_x509_field_ssl(X509_get_issuer_name(cert), "OU", buf, buf_len);
	if (!ret)
		ret = extract_x509_field_ssl(X509_get_issuer_name(cert), "O", buf, buf_len);

	return ret == 1 ? QString::fromUtf8(buf) : QLatin1String("");
}

QString X509CertificateUtil::get_common_name(X509 *cert)
{
	char buf[1024];
	int buf_len = 1024;

	int ret = extract_x509_field_ssl(X509_get_subject_name(cert), "CN", buf, buf_len);
	return ret == 1 ? QString::fromUtf8(buf) : QLatin1String("");
}

QString X509CertificateUtil::get_issuer_common_name(X509 *cert)
{
	char buf[1024];
	int buf_len = 1024;

	int ret = extract_x509_field_ssl(X509_get_issuer_name(cert), "CN", buf, buf_len);
	return ret == 1 ? QString::fromUtf8(buf) : QLatin1String("");
}

QDateTime X509CertificateUtil::get_not_before(X509 *cert)
{
	ASN1_TIME *at = X509_get_notBefore(cert);
	return get_time_from_asn1(at);
}

QDateTime X509CertificateUtil::get_not_after(X509 *cert)
{
	ASN1_TIME *at = X509_get_notAfter(cert);
	return get_time_from_asn1(at);
}

int X509CertificateUtil::get_sig_alg_nid(X509 *cert)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int nid = OBJ_obj2nid(cert->sig_alg->algorithm);
#else
	int nid = X509_get_signature_nid(cert);
#endif
	return nid;
}

QString X509CertificateUtil::get_sig_alg_name(X509 *cert)
{
	int nid = get_sig_alg_nid(cert);
	QString alg = QLatin1String(OBJ_nid2ln(nid));
	return alg;
}

QString X509CertificateUtil::get_serial_number(X509 *cert)
{
	asn1_int a(X509_get_serialNumber(cert));
	return a.toDec();
}

QString X509CertificateUtil::get_md5_fingerprint(X509 *cert, bool long_form)
{
	return get_fingerprint(cert, EVP_md5(), long_form);
}

QString X509CertificateUtil::get_sha1_fingerprint(X509 *cert, bool long_form)
{
	return get_fingerprint(cert, EVP_sha1(), long_form);
}

QString X509CertificateUtil::get_sha256_fingerprint(X509 *cert, bool long_form)
{
	return get_fingerprint(cert, EVP_sha256(), long_form);
}

#ifdef ENABLE_GUOMI
QString X509CertificateUtil::get_sm3_fingerprint(X509 *cert, bool long_form)
{
	return get_fingerprint(cert, EVP_sm3(), long_form);
}
#endif

bool X509CertificateUtil::is_tls_server(X509 *cert)
{
	return X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0);
}

bool X509CertificateUtil::is_tls_client(X509 *cert)
{
	return X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 0);
}

bool X509CertificateUtil::is_ca(X509 *cert)
{
	return X509_check_ca(cert);
}

bool X509CertificateUtil::contains(const QMap<X509*, QString>& x509_map, X509 *cert)
{
	if (cert) {
		QMapIterator<X509*, QString> it(x509_map);
		X509 *z_cert;
		while (it.hasNext()) {
			z_cert = it.next().key();
			if (z_cert && X509_cmp(z_cert, cert) == 0)
				return true;
		}
	}
	return false;
}

bool X509CertificateUtil::contains(const QList<X509*>& cert_list, X509 *cert)
{
	if (cert) {
		QListIterator<X509*> it(cert_list);
		X509 *z_cert;
		while (it.hasNext()) {
			z_cert = it.next();
			if (z_cert && X509_cmp(z_cert, cert) == 0)
				return true;
		}
	}
	return false;
}

#ifdef _WIN32
bool X509CertificateUtil::add_trusted_ca_to_system(X509 *cert)
{
	BIO *bio = BIO_new(BIO_s_mem());
	bool result = false;

	if (bio && i2d_X509_bio(bio, cert)) {
		unsigned char buf[8192];
		int read_len;

		if ((read_len = BIO_read(bio, buf, sizeof (buf))) > 0) {
			result = CertAddEncodedCertificateToSystemStore(TEXT("ROOT"), buf, read_len);
#ifdef _DEBUG
			if (!result) {
				LPWSTR lpMsgBuf = NULL;

				FormatMessage (
					FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, GetLastError(),
					MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US),
					(LPWSTR) &lpMsgBuf, 0, NULL);

				if (lpMsgBuf) {
					QString msg = QString::fromWCharArray(lpMsgBuf);
					LocalFree(lpMsgBuf);
					qDebug() << msg << "\n";
				}
			}
#endif
		}
	}

	if (bio)
		BIO_free(bio);
	return result;
}
#endif

bool X509CertificateUtil::add_cert_to_file(const QString& certFileName, const QList<X509*>& certs)
{
	QMap<X509*, QString> cert_map = load_from_file(certFileName);
	QList<X509*> cert_list = cert_map.keys();
	X509 *cert = NULL;
	bool result = true;

	for (int i = 0; i < certs.size(); ++i) {
		cert = certs.at(i);
		if (cert && !contains(cert_list, cert)) {
			if (is_ca(cert) && add_cert_to_file(certFileName, cert))
				cert_list.append(cert);
			else {
				result = false;
				break;
			}
		}
	}

	X509CertificateUtil::free_all_cert(cert_map);
	return result;
}

bool X509CertificateUtil::add_cert_to_file(const QString& certFileName, X509 *cert)
{
	// 如果存在, 先删除, 防止重复
	X509CertificateUtil::remove_cert_from_file(certFileName, cert);

	BIO *bio = BIO_new(BIO_s_mem());
	QFile certFile(certFileName);
	bool result = false;

	if (certFile.open(QIODevice::WriteOnly | QIODevice::Append)) {
		if (PEM_write_bio_X509(bio, cert)) {
			char buf[1024];
			int read_len;

			while ((read_len = BIO_read(bio, buf, sizeof (buf))) > 0)
				certFile.write(buf, read_len);
			result = true;
		}

		certFile.flush();
		certFile.close();
	}

	BIO_free(bio);
#ifndef _WIN32
	FileUtil::addPermissions(certFileName, FileUtil::ANY_BODY_READ);
#endif
	return result;
}

bool X509CertificateUtil::remove_cert_from_file(const QString& certFileName, X509 *cert)
{
#ifdef _WIN32
	FileUtil::setReadonlyAttribute(certFileName, false);
#endif
	/*
	 * 操作系统可能采用Local8Bit字符集，也可能采用UTF-8字符集，或其它...
	 * 文件名称从QString转换成const char*时采用那个字符集不好确定
	 * 使用QFile读取证书内容到缓存(由QT做字符集处理), 使用内存BIO; 不使用文件BIO
	 */
	QFile x_file(certFileName);
	if (!x_file.open(QIODevice::ReadOnly))
		return false;

#ifndef _WIN32
	FileUtil::addPermissions(certFileName, FileUtil::ANY_BODY_READ);
#endif

	QByteArray mem = x_file.readAll();
	x_file.close();

	BIO *bio = BIO_new_mem_buf(mem.data(), mem.size());
	X509 *x_cert;
	QList<X509*> allCerts;

	while (true) {
		x_cert = NULL;
		if (!PEM_read_bio_X509(bio, &x_cert, NULL, NULL)) {
			break;
		} else {
			if (X509_cmp(cert, x_cert) != 0)
				allCerts.append(x_cert);
		}
	}

	BIO_free(bio);

	bool result = true;
	bio = BIO_new(BIO_s_mem());

	for (int i = 0; i < allCerts.size(); ++i) {
		if (result) {
			if (PEM_write_bio_X509(bio, allCerts.at(i)) != 1)
				result = false;
		}
		X509_free(allCerts.at(i));
	}

	if (!result || !x_file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		BIO_free(bio);
		ERR_clear_error();
		return false;
	} else {
		char buf[1024];
		int len;

		while ((len = BIO_read(bio, buf, sizeof(buf))) > 0)
			x_file.write(buf, len);
		x_file.close();

		BIO_free(bio);
		ERR_clear_error();
		return true;
	}
}

void X509CertificateUtil::free_all_cert(const QMap<X509*, QString>& x509_map)
{
	X509 *x509;
	QMapIterator<X509*, QString> i(x509_map);

	while (i.hasNext()) {
		x509 = i.next().key();
		if (x509)
			X509_free(x509);
	}
}

void X509CertificateUtil::free_all_cert(QMap<int, X509*>& x509_map)
{
	X509 *x509;
	QMapIterator<int, X509*> it(x509_map);

	while (it.hasNext()) {
		it.next();
		x509 = it.value();
		if (x509)
			X509_free(x509);
	}
}

void X509CertificateUtil::free_all_cert(const QList<X509*>& cert_list)
{
	X509 *x509;
	QListIterator<X509*> i(cert_list);

	while (i.hasNext()) {
		x509 = i.next();
		if (x509)
			X509_free(x509);
	}
}

QString X509CertificateUtil::encode_to_base64(X509 *cert)
{
	QByteArray bytes;

	if (cert) {
		BIO *bio = BIO_new(BIO_s_mem());
		if (bio && i2d_X509_bio(bio, cert)) {
			char buf[8192];
			int len = 0;

			while ((len = BIO_read(bio, buf, sizeof (buf) - 1)) > 0)
				bytes.append(buf, len);
		}
		if (bio)
			BIO_free(bio);
	}
	return QLatin1String(bytes.toBase64());
}

X509* X509CertificateUtil::decode_from_base64(const QString& base64)
{
	QByteArray bytes = QByteArray::fromBase64(base64.toLocal8Bit());
	X509 *cert = NULL;
	BIO *bio = BIO_new(BIO_s_mem());

	if (bio) {
		BIO_write(bio, bytes.constData(), bytes.size());
		cert = d2i_X509_bio(bio, NULL);
		BIO_free(bio);
	}
	return cert;
}

QString X509CertificateUtil::get_fingerprint(X509 *cert, const EVP_MD *digest, bool long_form)
{
	QString fp = QLatin1String("");
	char zs[4];
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];

	X509_digest(cert, digest, md, &n);
	ERR_clear_error();
	for (int j = 0; j < (int) n; ++j) {
		if (long_form)
			sprintf(zs, "%02X%c",md[j], (j + 1 == (int) n) ? '\0' : ':');
		else
			sprintf(zs, "%02x", md[j]);
		fp += QLatin1String(zs);
	}
	return fp;
}

void X509CertificateUtil::strncpynt(char *dest, size_t dest_len, const char *src, size_t src_len)
{
#ifdef _WIN32
	strncpy_s(dest, dest_len, src, src_len);
	if (dest_len > 0)
		dest[dest_len - 1] = 0;
#else
	int npos = src_len < dest_len - 1 ? src_len : dest_len -1;
	strncpy(dest, src, src_len);
	if (npos > 0)
		dest[npos] = 0;
#endif
}

bool X509CertificateUtil::extract_x509_extension(X509 *cert, char *fieldname, char *out, int size)
{
	bool retval = false;
	char *buf = 0;
	GENERAL_NAMES *extensions;
	int nid = OBJ_txt2nid(fieldname);

	extensions = (GENERAL_NAMES *) X509_get_ext_d2i(cert, nid, NULL, NULL);
	if (extensions) {
		int i, numalts;

		/* get amount of alternatives, RFC2459 claims there MUST be at least one, but we don't depend on it... */
		numalts = sk_GENERAL_NAME_num(extensions);

		/* loop through all alternatives */
		for (i=0; i<numalts; i++) {
			/* get a handle to alternative name number i */
			const GENERAL_NAME *name = sk_GENERAL_NAME_value(extensions, i);

			switch (name->type) {
			case GEN_EMAIL:
				ASN1_STRING_to_UTF8((unsigned char**) &buf, name->d.ia5);
				if (strlen (buf) != name->d.ia5->length) {
					OPENSSL_free (buf);
				} else {
					strncpynt(out, size, buf, name->d.ia5->length);
					OPENSSL_free(buf);
					retval = true;
				}
				break;
			default:
				break;
			}
		}
		sk_GENERAL_NAME_free(extensions);
	}
	return retval;
}

bool X509CertificateUtil::extract_x509_field_ssl (X509_NAME *x509, const char *field_name, char *out, int size)
{
	int lastpos = -1;
	int tmp = -1;
	X509_NAME_ENTRY *x509ne = 0;
	ASN1_STRING *asn1 = 0;
	unsigned char *buf = (unsigned char *) 1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
	int nid = OBJ_txt2nid((char *) field_name);

	*out = '\0';
	do {
		lastpos = tmp;
		tmp = X509_NAME_get_index_by_NID(x509, nid, lastpos);
	} while (tmp > -1);

	/* Nothing found */
	if (lastpos == -1)
		return 0;

	x509ne = X509_NAME_get_entry(x509, lastpos);
	if (!x509ne)
		return 0;

	asn1 = X509_NAME_ENTRY_get_data(x509ne);
	if (!asn1)
		return 0;

	tmp = ASN1_STRING_to_UTF8(&buf, asn1);
	if (tmp <= 0)
		return 0;


	bool ret = (strlen((char *) buf) < (size_t) size) ? 1: 0;
	if (ret)
		strncpynt(out, size, (char *) buf, strlen((char *) buf));
	OPENSSL_free (buf);

	return ret;
}

QDateTime X509CertificateUtil::get_time_from_asn1(const ASN1_TIME *a_time)
{
    size_t lTimeLength = a_time->length;
    char *pString = (char *) a_time->data;

    if (a_time->type == V_ASN1_UTCTIME) {

        char lBuffer[24];
        char *pBuffer = lBuffer;

        if ((lTimeLength < 11) || (lTimeLength > 17))
            return QDateTime();

        memcpy(pBuffer, pString, 10);
        pBuffer += 10;
        pString += 10;

        if ((*pString == 'Z') || (*pString == '-') || (*pString == '+')) {
            *pBuffer++ = '0';
            *pBuffer++ = '0';
        } else {
            *pBuffer++ = *pString++;
            *pBuffer++ = *pString++;
            // Skip any fractional seconds...
            if (*pString == '.') {
                pString++;
                while ((*pString >= '0') && (*pString <= '9'))
                    pString++;
            }
        }

        *pBuffer++ = 'Z';
        *pBuffer++ = '\0';

        time_t lSecondsFromUCT;
        if (*pString == 'Z') {
            lSecondsFromUCT = 0;
        } else {
            if ((*pString != '+') && (*pString != '-'))
                return QDateTime();

            lSecondsFromUCT = ((pString[1] - '0') * 10 + (pString[2] - '0')) * 60;
            lSecondsFromUCT += (pString[3] - '0') * 10 + (pString[4] - '0');
            lSecondsFromUCT *= 60;
            if (*pString == '-')
                lSecondsFromUCT = -lSecondsFromUCT;
        }

        tm lTime;
        lTime.tm_sec = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
        lTime.tm_min = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
        lTime.tm_hour = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
        lTime.tm_mday = ((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0');
        lTime.tm_mon = (((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0')) - 1;
        lTime.tm_year = ((lBuffer[0] - '0') * 10) + (lBuffer[1] - '0');
        if (lTime.tm_year < 50)
            lTime.tm_year += 100; // RFC 2459

        QDate resDate(lTime.tm_year + 1900, lTime.tm_mon + 1, lTime.tm_mday);
        QTime resTime(lTime.tm_hour, lTime.tm_min, lTime.tm_sec);

        QDateTime result(resDate, resTime, Qt::UTC);
        result = result.addSecs(lSecondsFromUCT);
        return result;

    } else if (a_time->type == V_ASN1_GENERALIZEDTIME) {

        if (lTimeLength < 15)
            return QDateTime(); // hopefully never triggered

        // generalized time is always YYYYMMDDHHMMSSZ (RFC 2459, section 4.1.2.5.2)
        tm lTime;
        lTime.tm_sec = ((pString[12] - '0') * 10) + (pString[13] - '0');
        lTime.tm_min = ((pString[10] - '0') * 10) + (pString[11] - '0');
        lTime.tm_hour = ((pString[8] - '0') * 10) + (pString[9] - '0');
        lTime.tm_mday = ((pString[6] - '0') * 10) + (pString[7] - '0');
        lTime.tm_mon = (((pString[4] - '0') * 10) + (pString[5] - '0'));
        lTime.tm_year = ((pString[0] - '0') * 1000) + ((pString[1] - '0') * 100) +
                        ((pString[2] - '0') * 10) + (pString[3] - '0');

        QDate resDate(lTime.tm_year, lTime.tm_mon, lTime.tm_mday);
        QTime resTime(lTime.tm_hour, lTime.tm_min, lTime.tm_sec);

        QDateTime result(resDate, resTime, Qt::UTC);
        return result;

    } else {
        qWarning("unsupported date format detected");
        return QDateTime();
    }
}
