#include <QByteArray>
#include <QFile>

#include "pkcs12_util.h"

Pkcs12Util::Pkcs12Util()
{
}

bool Pkcs12Util::copyPkcs12(const QString& p12File, const QByteArray& passphrase,
		const QString& new_p12File, const QByteArray& new_passphrase)
{
	bool result = false;
	EVP_PKEY *prvkey = NULL;
	X509 *cert = NULL;
	QList<X509*> ca;

	if (readPkcs12(p12File, passphrase, &prvkey, &cert, &ca)) {
		result = writePkcs12(new_p12File, new_passphrase, prvkey, cert, &ca);
		if (prvkey)
			EVP_PKEY_free(prvkey);
		if (cert)
			X509_free(cert);

		QListIterator<X509*> i(ca);
		while (i.hasNext()) {
			cert = i.next();
			if (cert)
				X509_free(cert);
		}
	}
	return result;
}

bool Pkcs12Util::readPkcs12(const QString& p12File, const QByteArray& passphrase, EVP_PKEY **prvkey,
		X509 **cert, QList<X509*> *ca)
{
	if (prvkey)
		*prvkey = NULL;
	if (cert)
		*cert = NULL;

	/*
	 * 操作系统可能采用Local8Bit字符集，也可能采用UTF-8字符集，或其它...
	 * 文件名称从QString转换成const char*时采用那个字符集不好确定
	 * 使用QFile读取证书内容到缓存(由QT做字符集处理), 使用内存BIO; 不使用文件BIO
	 */
	QFile x_file(p12File);
	if (!x_file.open(QIODevice::ReadOnly))
		return false;

	QByteArray mem = x_file.readAll();
	x_file.close();

	BIO *bio = BIO_new_mem_buf(mem.data(), mem.size());
	PKCS12 *pkcs12 = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);
	if (!pkcs12)
		return false;

	EVP_PKEY *x_prvkey = NULL;
	X509 *x_cert = NULL;
	STACK_OF(X509) *x_certstack = sk_X509_new_null();
	int result = 0;

	if (!passphrase.isEmpty())
		result = PKCS12_parse(pkcs12, passphrase.constData(), &x_prvkey, &x_cert, &x_certstack);
	else
		result = PKCS12_parse(pkcs12, NULL, &x_prvkey, &x_cert, &x_certstack);

	if (cert)
		*cert = x_cert;
	else
		X509_free(x_cert);
	if (prvkey)
		*prvkey = x_prvkey;
	else
		EVP_PKEY_free(x_prvkey);

	if (x_certstack) {
		for (int i = 0; i < sk_X509_num(x_certstack); ++i) {
			if (ca)
				ca->append(sk_X509_value(x_certstack, i));
			else
				X509_free(sk_X509_value(x_certstack, i));
		}
		sk_X509_free(x_certstack);
	}

	PKCS12_free(pkcs12);
	ERR_clear_error();

	return result != 0 ? true : false;
}

bool Pkcs12Util::writePkcs12(const QString& p12File, const QByteArray& passphrase, EVP_PKEY *prvkey,
		X509 *cert, QList<X509*> *ca)
{
	// 生成证书堆栈
	STACK_OF(X509) *x_certstack = NULL;
	if (ca) {
		x_certstack = sk_X509_new_null();
		for (int i = 0; i < ca->size(); ++i) {
			X509 *cur_x509 = ca->at(i);
			sk_X509_push(x_certstack, cur_x509);
		}
	}

	/*
	 * 操作系统可能采用Local8Bit字符集，也可能采用UTF-8字符集，或其它...
	 * 文件名称从QString转换成const char*时采用那个字符集不好确定
	 * 使用QFile读取证书内容到缓存(由QT做字符集处理), 使用内存BIO; 不使用文件BIO
	 */
	BIO *bio = BIO_new(BIO_s_mem());
	int result = 0;
	PKCS12 *pkcs12 = NULL;

	if (!passphrase.isEmpty())
		pkcs12 = PKCS12_create((char*) passphrase.constData(), NULL, prvkey, cert, x_certstack, 0, 0, 0, 0, 0);
	else
		pkcs12 = PKCS12_create((char*) ""/* 使用NULL指针时，firefox导入失败! */, NULL, prvkey, cert, x_certstack, 0, 0, 0, 0, 0);
	if (pkcs12) {
		result = i2d_PKCS12_bio(bio, pkcs12);
		PKCS12_free(pkcs12);
	}

	if (x_certstack)
		sk_X509_free(x_certstack);

	if (result) {
		QFile x_file(p12File);
		if (x_file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
			char buf[1024];
			int len;

			while ((len = BIO_read(bio, buf, sizeof(buf))) > 0)
				x_file.write(buf, len);
			x_file.close();
		} else
			result = 0;
	}

	BIO_free(bio);

	return result != 0 ? true : false;
}
