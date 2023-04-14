#ifndef __GENERIC_RESULT_H__
#define __GENERIC_RESULT_H__

#include "../config/config.h"

#include <QString>
#include <QVariant>
#include <QMap>
#include <QDataStream>

class GenericResult
{
public:
	// �����������ƶ���
	static const QString VPN_CONFIG_ID;

	// code==0, ��ʾ�ɹ�, ����ֵΪ�������
	explicit GenericResult(int _code, const QString& _reason = QString())
		: code(_code), reason(_reason) {
	}
	GenericResult() : code(0) {
	}

	int getCode() const {
		return code;
	}
	void setCode(int code) {
		this->code = code;
	}

	const QString& getReason() const {
		return reason;
	}
	void setReason(const QString& reason) {
		this->reason = reason;
	}

	bool hasAttribute(const QString& name) const {
		return this->attributes.contains(name);
	}

	QVariant getAttribute(const QString& name) const {
		return this->attributes.value(name);
	}

	void setAttribute(const QString& name, const QVariant& value) {
		this->attributes.insert(name, value);
	}

private:
	friend QDataStream& operator<<(QDataStream& stream, const GenericResult& result);
	friend QDataStream& operator>>(QDataStream& stream, GenericResult& result);

	int code;	// 0 ��ʾ�ɹ�
	QString reason;
	QMap<QString, QVariant> attributes;

	// ÿ�����serial_uid����ͬ
	static const quint32 serial_uid;

};

#endif
