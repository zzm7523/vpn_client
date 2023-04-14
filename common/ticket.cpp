#include "ticket.h"

const unsigned int Ticket::serial_uid = 0x082;

static void int32ToBytes(qint32 i, QByteArray &buffer) 
{
	buffer.append((char) (i >> 24));
	buffer.append((char) (i >> 16));
	buffer.append((char) (i >> 8));
	buffer.append((char) (i >> 0));
}

static void int64ToBytes(qint64 i, QByteArray &buffer) 
{
	buffer.append((char) (i >> 56));
	buffer.append((char) (i >> 48));
	buffer.append((char) (i >> 40));
	buffer.append((char) (i >> 32));
	buffer.append((char) (i >> 24));
	buffer.append((char) (i >> 16));
	buffer.append((char) (i >> 8));
	buffer.append((char) (i >> 0));
}

static qint32 getInt32FromBytes(QByteArray &buffer, qint32 start_idx)
{
	if (start_idx + 4 > buffer.size()) {
		return -1;
	}

	return ((qint32) buffer.at(start_idx + 0) & 0xff) << 24 | ((qint32) buffer.at(start_idx + 1) & 0xff) << 16 |
		((qint32) buffer.at(start_idx + 2) & 0xff) << 8 | ((qint32) buffer.at(start_idx + 3) & 0xff) << 0;
}

static qint64 getInt64FromBytes(QByteArray &buffer, qint32 start_idx)
{
	if (start_idx + 8 > buffer.size()) {
		return -1;
	}
	return ((qint64) buffer.at(start_idx + 0) & 0xff) << 56 | ((qint64) buffer.at(start_idx + 1) & 0xff) << 48 |
		((qint64) buffer.at(start_idx + 2) & 0xff) << 40 | ((qint64) buffer.at(start_idx + 3) & 0xff) << 32 |
		((qint64) buffer.at(start_idx + 4) & 0xff) << 24 | ((qint64) buffer.at(start_idx + 5) & 0xff) << 16 |
		((qint64) buffer.at(start_idx + 6) & 0xff) << 8 | ((qint64) buffer.at(start_idx + 7) & 0xff) << 0;
}

QString Ticket::encode(const Ticket& ticket)
{
	QByteArray buffer;
	int32ToBytes(4, buffer);	// 输出创建时间
	int64ToBytes(ticket.createTime, buffer);

	int32ToBytes(4, buffer);	// 输出有效期
	int64ToBytes(ticket.validity, buffer);

	int32ToBytes(ticket.attributes.size(), buffer);	// 输出票据数据

	QMap<QString, QString>::const_iterator it;
	QByteArray name, value;
	for (it = ticket.attributes.constBegin(); it != ticket.attributes.constEnd(); ++it) {
		name = it.key().toUtf8();
		int32ToBytes(name.length(), buffer);
		buffer.append(name);

		if (it.value().isNull()) {
			int32ToBytes(-1, buffer);
		} else {
			value = it.value().toUtf8();
			int32ToBytes(value.length(), buffer);
			buffer.append(value);
		}
	}

	return QString::fromUtf8(buffer.toBase64());
}

Ticket Ticket::decode(const QString& string)
{
	QByteArray buffer = QByteArray::fromBase64(string.toUtf8());
	qint32 start_idx = 0;		
	getInt32FromBytes(buffer, start_idx);
	start_idx += 4;
	qint64 createTime = getInt64FromBytes(buffer, start_idx);
	start_idx += 8;

	getInt32FromBytes(buffer, start_idx);
	start_idx += 4;
	qint64 validity = getInt64FromBytes(buffer, start_idx);
	start_idx += 8;

	qint32 attrsize = getInt32FromBytes(buffer, start_idx);
	start_idx += 4;

	QMap<QString, QString> attributes;
	qint32 namelen, valuelen;
	QByteArray name, value;
	for (int i = 0; i < attrsize; ++i) {
		namelen = getInt32FromBytes(buffer, start_idx);
		start_idx += 4;
		name = buffer.mid(start_idx, namelen);
		start_idx += namelen;

		valuelen = getInt32FromBytes(buffer, start_idx);
		if (valuelen < 0) {
			start_idx += 4;
			value = QByteArray();
		} else {
			start_idx += 4;
			value = buffer.mid(start_idx, valuelen);
			start_idx += valuelen;
		}

		attributes.insert(QString::fromUtf8(name), QString::fromUtf8(value));
	}

	return Ticket(createTime, validity, attributes);
}

Ticket::Ticket()
	: createTime(-1), validity(-1)
{
}

Ticket::Ticket(qint64 _createTime, qint64 _validity)
	: createTime(_createTime), validity(_validity)
{
}

Ticket::Ticket(qint64 _createTime, qint64 _validity, const QMap<QString, QString>& _attributes)
	: createTime(_createTime), validity(_validity), attributes(_attributes)
{
}

qint64 Ticket::getCreateTime() const
{
	return createTime;
}

void Ticket::setCreateTime(qint64 createTime)
{
	this->createTime = createTime;
}

qint64 Ticket::getValidity() const
{
	return validity;
}

void Ticket::setValidity(qint64 validity)
{
	this->validity = validity;
}

bool Ticket::hasAttribute(const QString& name) const
{
	return attributes.contains(name);
}

const QString Ticket::getAttribute(const QString& name) const
{
	return attributes.value(name);
}

void Ticket::setAttribute(const QString& name, const QString& value)
{
	attributes.insert(name, value);
}

bool Ticket::isEmpty() const
{
	return attributes.isEmpty();
}

bool Ticket::isValid() const
{
	return !isEmpty() && createTime != -1 && validity != -1
		&& QDateTime::currentMSecsSinceEpoch() < (createTime + validity);
}

bool Ticket::operator == (const Ticket& other) const
{
	return createTime == other.createTime && validity == other.validity && attributes == other.attributes;
}

bool Ticket::operator != (const Ticket& other) const
{
	return createTime != other.createTime || validity != other.validity || attributes != other.attributes;
}

QDataStream& operator<<(QDataStream& stream, const Ticket& ticket)
{
	stream << Ticket::serial_uid << ticket.createTime << ticket.validity << ticket.attributes;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, Ticket& ticket)
{
	unsigned int local_serial_uid;

	stream >> local_serial_uid >> ticket.createTime >> ticket.validity >> ticket.attributes;

	Q_ASSERT(Ticket::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}
