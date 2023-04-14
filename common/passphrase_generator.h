#ifndef __PASSPHRASE_GENERATOR_H__
#define __PASSPHRASE_GENERATOR_H__

#include "../config/config.h"

#include <QString>
#include <QByteArray>

class PassphraseGenerator
{
public:
	static QByteArray generatePassphrase(const int length, const int rotate, const QString& salt);
	static QByteArray generatePKCS12Passphrase();
	static QByteArray generateCredentialPassphrase();

};

#endif
