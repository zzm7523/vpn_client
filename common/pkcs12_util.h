#ifndef __PKCS12_H__
#define __PKCS12_H__

#include "../config/config.h"

#include <QString>
#include <QByteArray>
#include <QList>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

class Pkcs12Util
{
public:
	static bool copyPkcs12(const QString& p12File, const QByteArray& passphrase,
		const QString& new_p12File, const QByteArray& new_passphrase);

	static bool readPkcs12(const QString& p12File, const QByteArray& passphrase, EVP_PKEY **prvkey,
		X509 **cert, QList<X509*> *ca = NULL);

	static bool writePkcs12(const QString& p12File, const QByteArray& passphrase, EVP_PKEY *prvkey,
		X509 *cert, QList<X509*> *ca = NULL);

private:
	Pkcs12Util();

};

#endif
