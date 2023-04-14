#include <QDebug>

#include "cipher.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

QByteArray Cipher::generateKey(const int keyLen, const int rotate, const QByteArray& passphrase, bool &success)
{
	QByteArray key;
	unsigned char md[EVP_MAX_MD_SIZE];
	QByteArray source(passphrase);
	
	do {
		memset(md, 0x0, EVP_MAX_MD_SIZE);
		for (int i = 0; i < rotate; ++i) {
			source.append(QString::number(i).toUtf8());
			SHA1((unsigned char*) source.data(), source.size(), md);
			source.append((const char*) md, SHA_DIGEST_LENGTH);
		}
		key.append((const char*) md, SHA_DIGEST_LENGTH);

	} while (key.size() < keyLen);

	success = true;
	return key.toBase64().mid(0, keyLen);
}

// 根据机器软硬件特征生成初始向量
QByteArray Cipher::generateIV(const int ivLen, const int rotate, const QByteArray& passphrase, bool &success)
{
	QByteArray iv;
	unsigned char md[EVP_MAX_MD_SIZE];
	QByteArray source(passphrase);

	do {
		memset(md, 0x0, EVP_MAX_MD_SIZE);
		for (int i = 0; i < rotate; ++i) {
			MD5((unsigned char*) source.data(), source.size(), md);
			source.append((const char*) md, MD5_DIGEST_LENGTH);
			source.append(QString::number(i).toUtf8());
		}
		iv.append((const char*) md, MD5_DIGEST_LENGTH);

	} while (iv.size() < ivLen);

	success = true;
	return iv.toBase64().mid(0, ivLen);
}

Cipher::Cipher(const QString& cipherName, const QByteArray& key, const QByteArray& iv)
	: cipher(NULL)
{
	Q_ASSERT(!cipherName.isEmpty() && !key.isEmpty() && !iv.isEmpty());
	this->key = key;
	this->iv = iv;
	this->ctx = EVP_CIPHER_CTX_new();
	cipher = EVP_get_cipherbyname(cipherName.toLocal8Bit());
}

Cipher::~Cipher()
{
	if (this->ctx)
		EVP_CIPHER_CTX_free(this->ctx);
}

QByteArray Cipher::encrypt(const QByteArray& plaintext, bool &success)
{
	QByteArray ciphertext;

	success = false;

	if (cipher && key.size() >= EVP_CIPHER_key_length(cipher) && iv.size() >= EVP_CIPHER_iv_length(cipher)) {
		unsigned char *buf = (unsigned char*) malloc (plaintext.size() + EVP_MAX_BLOCK_LENGTH);
		int buf_len = plaintext.size() + EVP_MAX_BLOCK_LENGTH;

		EVP_CipherInit_ex(ctx, cipher, NULL, (unsigned char*) key.data(), (unsigned char*) iv.data(), 1);
		EVP_CipherUpdate(ctx, buf, &buf_len, (unsigned char*) plaintext.data(), plaintext.size());
		ciphertext.append((const char*) buf, buf_len);

		buf_len = plaintext.size() + EVP_MAX_BLOCK_LENGTH;
		EVP_CipherFinal_ex(ctx, buf, &buf_len);
		if (buf_len > 0)
			ciphertext.append((const char*) buf, buf_len);
		if (buf)
			free (buf);
		success = true;
	}

	return ciphertext;
}

QByteArray Cipher::decrypt(const QByteArray& ciphertext, bool &success)
{
	QByteArray plaintext;

	success = false;

	if (cipher && key.size() >= EVP_CIPHER_key_length(cipher) && iv.size() >= EVP_CIPHER_iv_length(cipher)) {
		unsigned char *buf = (unsigned char*) malloc(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
		int buf_len = ciphertext.size() + EVP_MAX_BLOCK_LENGTH;

		EVP_CipherInit_ex(ctx, cipher, NULL, (unsigned char*) key.data(), (unsigned char*) iv.data(), 0);
		EVP_CipherUpdate(ctx, buf, &buf_len, (unsigned char*) ciphertext.data(), ciphertext.size());
		plaintext.append((const char*) buf, buf_len);

		buf_len = ciphertext.size() + EVP_MAX_BLOCK_LENGTH;
		EVP_CipherFinal_ex(ctx, buf, &buf_len);
		if (buf_len > 0)
			plaintext.append((const char*) buf, buf_len);
		if (buf)
			free (buf);
		success = true;
	}

	return plaintext;
}
