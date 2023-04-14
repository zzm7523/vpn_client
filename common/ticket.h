#ifndef __TICKET_H__
#define __TICKET_H__

#include "../config/config.h"

#include <QString>
#include <QMap>
#include <QDateTime>
#include <QDataStream>

class Ticket
{
public:
	static QString encode(const Ticket& ticket);
	static Ticket decode(const QString& string);

	Ticket();
	Ticket(qint64 createTime, qint64 validity);
	Ticket(qint64 createTime, qint64 validity, const QMap<QString, QString>& attributes);

	qint64 getCreateTime() const;
	void setCreateTime(qint64 createTime);

	qint64 getValidity() const;
	void setValidity(qint64 validity);

	bool hasAttribute(const QString& name) const;
	const QString getAttribute(const QString& name) const;
	void setAttribute(const QString& name, const QString& value);

	bool isEmpty() const;
	bool isValid() const;

	bool operator == (const Ticket& other) const;
	bool operator != (const Ticket& other) const;

private:
	friend QDataStream& operator<<(QDataStream& stream, const Ticket& ticket);
	friend QDataStream& operator>>(QDataStream& stream, Ticket& ticket);

	qint64 createTime;  // 自从标准基准时间(epoch, 即 1970年1月1日 00:00:00 GMT）以来的指定毫秒数。 
	qint64 validity;    // 毫秒
	QMap<QString, QString> attributes;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(Ticket)

#endif
