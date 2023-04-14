#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "../config/config.h"

#include <QString>
#include <QVariant>
#include <QMap>
#include <QDataStream>

class Context
{
public:
	static const QString LANG;
	static const QString USER_IDENTIFY;
	static const QString SESSION_IDENTIFY;
	static const QString VPN_CONNECT_SEQUENCE;
	static const QString TRUNC_VPN_LOG;
	static const QString POLICY_ENGINE_COUNTER;
	static const QString TERMINAL_BIND;
	static const QString PIN_ERROR;
	static const QString AUTH_ERROR;
	static const QString PROXY_AUTH_ERROR;

	// 这三个对象比较大, 不要放在全局上下文
	static const QString VPN_CONFIG;
	static const QString VPN_TUNNEL;
	static const QString REMOVED_ENCRYPT_DEVICES;

	static Context& getDefaultContext();

	Context() {
	}

	Context(const QString& name, const QVariant& value) {
		attrs.insert(name, value);
	}

	void clear() {
		attrs.clear();
	}

	void removeAttribute(const QString& name) {
		attrs.remove(name);
	}

	bool hasAttribute(const QString& name) const {
		return attrs.contains(name);
	}

	QVariant getAttribute(const QString& name) const {
		return attrs.value(name);
	}

	void setAttribute(const QString& name, const QVariant& value) {
		attrs.insert(name, value);
	}

private:
	friend QDataStream& operator<<(QDataStream& stream, const Context& ctx);
	friend QDataStream& operator>>(QDataStream& stream, Context& ctx);

	QMap<QString, QVariant> attrs;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};

bool userIdentifyEqual(const Context& c1, const Context& c2);
bool sessionIdentifyEqual(const Context& c1, const Context& c2);

#endif
