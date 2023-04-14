#ifndef __SERVER_ENDPOINT_H__
#define __SERVER_ENDPOINT_H__

#include "../config/config.h"
#include "common.h"

#include <QString>
#include <QDataStream>

class ServerEndpoint
{
public:
	enum Potocol
	{
		Udp  = 0,
		Udp6 = 1,
		Tcp  = 2,
		Tcp6 = 3
	};

	static QString protocol2String(ServerEndpoint::Potocol protocol);
	static ServerEndpoint::Potocol string2Protocol(const QString& protocolString);

	explicit ServerEndpoint(const QString& host, int port = VPN_PORT, ServerEndpoint::Potocol protocol = ServerEndpoint::Udp);
	ServerEndpoint();
	// 缺省拷贝构造函数就可以了

	bool isEmpty() const {
		return this->host.isEmpty() || this->port <= 0;
	}

	void clear() {
		this->host.clear();
		this->port = VPN_PORT;
		this->protocol = ServerEndpoint::Udp;
	}

	const QString& getHost() const {
		return host;
	}
	void setHost(const QString& host) {
		this->host = host;
	}

	int getPort() const {
		return port;
	}
	void setPort(int port) {
		this->port = port;
	}

	ServerEndpoint::Potocol getProtocol() const {
		return protocol;
	}
	void setProtocol(ServerEndpoint::Potocol protocol) {
		this->protocol = protocol;
	}

	bool operator == (const ServerEndpoint& other) const;

private:
	friend QDataStream& operator<<(QDataStream& stream, const ServerEndpoint& serverEndpoint);
	friend QDataStream& operator>>(QDataStream& stream, ServerEndpoint& serverEndpoint);

	QString host;
	int port;
	ServerEndpoint::Potocol protocol;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(ServerEndpoint)

bool serverEndpointsEqual(const QList<ServerEndpoint>& sp1, const QList<ServerEndpoint>& sp2);

#endif
