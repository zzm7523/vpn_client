#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "../config/config.h"

#include <QString>
#include <QByteArray>

#include <openssl/evp.h>

class Cipher
{
public:
	static QByteArray generateKey(const int keyLen, const int rotate, const QByteArray& passphrase, bool &success);
	static QByteArray generateIV(const int ivLen, const int rotate, const QByteArray& passphrase, bool &success);

	Cipher(const QString& cipherName, const QByteArray& key, const QByteArray& iv);
	~Cipher();

	QByteArray encrypt(const QByteArray& plaintext, bool &success);
	QByteArray decrypt(const QByteArray& ciphertext, bool &success);

private:
	QByteArray key;
	QByteArray iv;
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;

};

#endif
