#include "generic_result.h"

const unsigned int GenericResult::serial_uid = 0x673;

const QString GenericResult::VPN_CONFIG_ID = QLatin1String("vpn_config_id");

QDataStream& operator<<(QDataStream& stream, const GenericResult& result)
{
	stream << GenericResult::serial_uid << result.code << result.reason << result.attributes;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, GenericResult& result)
{
	unsigned int local_serial_uid;

	stream >> local_serial_uid >> result.code >> result.reason >> result.attributes;

	Q_ASSERT(GenericResult::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}
