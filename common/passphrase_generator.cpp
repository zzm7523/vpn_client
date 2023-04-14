#include "common.h"
#include "cipher.h"
#include "file_util.h"
#include "system_info.h"

#include "passphrase_generator.h"

#include <QDir>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define CREDENTIALS_PASSPHRASE_LENGTH	19	// 必须小于 < 64
#define CREDENTIALS_PASSPHRASE_ROTATE	157
#define PKCS12_PASSPHRASE_LENGTH		21	// 必须小于 < 64
#define PKCS12_PASSPHRASE_ROTATE		173

QByteArray PassphraseGenerator::generatePassphrase(const int length, const int rotate, const QString& salt)
{
	QByteArray source, passphrase;
	unsigned char md[EVP_MAX_MD_SIZE];

	source.append(FileUtil::getAppSavePath(QLatin1String(VPN_CONFIG_DIR_NAME)).toUtf8());

	// !!修改实现要谨慎!!, 不兼容的修改会导致以前加密的信息无法解密

	// 通过WMI获取硬件信息可能会很慢, 在XP虚拟机看见过几十秒

	source.append(QString::number(length).toUtf8()).append(QString::number(rotate).toUtf8());
	source.append("sd$fg%ky&vg0563kl;:q?<##").append(salt.toUtf8());

	// 不要使用CPU信息, 用户升级CPU的可能性比较大
	// 不要使用硬盘信息, 用户更换硬盘的可能性比较大

	// 使用静态MAC地址, 网卡一般都集成到主板, 用户更换主板的可能性比较小
	QStringList macs = SystemInfo::getMacs();
	for (int i = 0; i < macs.size(); ++i)
		source.append(macs.at(i).toUtf8());

	do {
		memset (md, 0x0, EVP_MAX_MD_SIZE);
		for (int i = 0; i < rotate; ++i) {
			source.append(QString::number(i).toUtf8());
			SHA1((unsigned char*) source.data(), source.size(), md);
			source.append((const char*) md, SHA_DIGEST_LENGTH);
		}
		passphrase.append((const char*) md, SHA_DIGEST_LENGTH);

	} while (passphrase.size() < length);

	return passphrase.mid(0, length);
}

QByteArray PassphraseGenerator::generatePKCS12Passphrase()
{
	QByteArray bytes = generatePassphrase(PKCS12_PASSPHRASE_LENGTH, PKCS12_PASSPHRASE_ROTATE,
		QDir(FileUtil::getAppSavePath(QLatin1String(VPN_CONFIG_DIR_NAME))).absoluteFilePath("PKCS12"));
	return bytes.toBase64();	/* 密码传递, 交互, 和c字符串兼容 */
}

QByteArray PassphraseGenerator::generateCredentialPassphrase()
{
	QByteArray bytes = generatePassphrase(CREDENTIALS_PASSPHRASE_LENGTH, CREDENTIALS_PASSPHRASE_ROTATE,
		QDir(FileUtil::getAppSavePath(QLatin1String(VPN_CONFIG_DIR_NAME))).absoluteFilePath("CREDS"));
	return bytes.toBase64();	/* 密码传递, 交互, 和c字符串兼容 */
}
