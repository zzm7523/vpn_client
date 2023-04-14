#ifndef __TLS_AUTH_H__
#define __TLS_AUTH_H__

#include "../config/config.h"

#include <QString>
#include <QFile>
#include <QDataStream>

#define KEY_DIRECTION_BIDIRECTIONAL 0 /* same keys for both directions */
#define KEY_DIRECTION_NORMAL        1 /* encrypt with keys[0], decrypt with keys[1] */
#define KEY_DIRECTION_INVERSE       2 /* encrypt with keys[1], decrypt with keys[0] */

class TLSAuth
{
public:
	TLSAuth(const QString& fileName, const QString& auth, int direction);
	TLSAuth();

	bool isEmpty() const;
	void clear();

	const QString& getFileName() const;
	void setFileName(const QString& fileName);

	const QString& getAuth() const;
	void setAuth(const QString& auth);

	int getDirection() const;
	void setDirection(int direction);

	bool operator == (const TLSAuth& other) const;
	bool operator != (const TLSAuth& other) const;

private:
	friend QDataStream& operator<<(QDataStream& stream, const TLSAuth& tlsAuth);
	friend QDataStream& operator>>(QDataStream& stream, TLSAuth& tlsAuth);

	QString fileName;
	QString auth;
	int direction;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(TLSAuth)

#endif
