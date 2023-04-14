#include "server_endpoint.h"

const unsigned int ServerEndpoint::serial_uid = 0x079;

QString ServerEndpoint::protocol2String(ServerEndpoint::Potocol protocol)
{
	switch (protocol) {
	case ServerEndpoint::Udp:
		return QLatin1String("UDP");
	case ServerEndpoint::Udp6:
		return QLatin1String("UDP6");
	case ServerEndpoint::Tcp:
		return QLatin1String("TCP");
	case ServerEndpoint::Tcp6:
		return QLatin1String("TCP6");
	default:
		return QLatin1String("UNKNOWN");
	}
}

ServerEndpoint::Potocol ServerEndpoint::string2Protocol(const QString& protocolString)
{
	if (protocolString.compare(QLatin1String("UDP"), Qt::CaseInsensitive) == 0)
		return ServerEndpoint::Udp;
	else if (protocolString.compare(QLatin1String("UDP6"), Qt::CaseInsensitive) == 0)
		return ServerEndpoint::Udp6;
	else if (protocolString.compare(QLatin1String("TCP"), Qt::CaseInsensitive) == 0)
		return ServerEndpoint::Tcp;
	else if (protocolString.compare(QLatin1String("TCP6"), Qt::CaseInsensitive) == 0)
		return ServerEndpoint::Tcp6;
	else
		return ServerEndpoint::Udp;
}

ServerEndpoint::ServerEndpoint(const QString& _host, int _port, ServerEndpoint::Potocol _protocol)
	: host(_host), port(_port), protocol(_protocol)
{
}

ServerEndpoint::ServerEndpoint()
	: port(VPN_PORT), protocol(ServerEndpoint::Udp)
{
}

bool ServerEndpoint::operator == (const ServerEndpoint& other) const
{
	return this->host.compare(other.host, Qt::CaseInsensitive) == 0 && this->port == other.port
		&& this->protocol == other.protocol;
}

QDataStream& operator<<(QDataStream& stream, const ServerEndpoint& serverEndpoint)
{
	stream << ServerEndpoint::serial_uid << serverEndpoint.host << serverEndpoint.port
		<< static_cast<quint32>(serverEndpoint.protocol);
	return stream;
}

QDataStream& operator>>(QDataStream& stream, ServerEndpoint& serverEndpoint)
{
	unsigned int local_serial_uid, _protocol;

	stream >> local_serial_uid >> serverEndpoint.host >> serverEndpoint.port >> _protocol;
	serverEndpoint.protocol = static_cast<ServerEndpoint::Potocol>(_protocol);

	Q_ASSERT(ServerEndpoint::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}

bool serverEndpointsEqual(const QList<ServerEndpoint>& sp1, const QList<ServerEndpoint>& sp2)
{
	// ◊¢ ÕµÙ, ServerEndpointø…ƒ‹÷ÿ∏¥
/*
	if (sp1.size() != sp2.size())
		return false;
*/

	for (int i = 0; i < sp1.size(); ++i) {
		if (!sp2.contains(sp1.at(i)))
			return false;
	}

	for (int i = 0; i < sp2.size(); ++i) {
		if (!sp1.contains(sp2.at(i)))
			return false;
	}

	return true;
}
