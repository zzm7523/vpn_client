#include "context.h"

const unsigned int Context::serial_uid = 0x017;

const QString Context::LANG = QLatin1String("lang");
const QString Context::USER_IDENTIFY = QLatin1String("user_identify");
const QString Context::SESSION_IDENTIFY = QLatin1String("session_identify");
const QString Context::VPN_CONNECT_SEQUENCE = QLatin1String("vpn_connect_sequence");
const QString Context::TRUNC_VPN_LOG = QLatin1String("trunc_vpn_log");
const QString Context::TERMINAL_BIND = QLatin1String("terminal_bind");
const QString Context::PIN_ERROR = QLatin1String("pin_error");
const QString Context::AUTH_ERROR = QLatin1String("auth_error");
const QString Context::PROXY_AUTH_ERROR = QLatin1String("proxy_auth_error");
const QString Context::POLICY_ENGINE_COUNTER = QLatin1String("policy_engine_counter");

const QString Context::VPN_CONFIG = QLatin1String("vpn_config");
const QString Context::VPN_TUNNEL = QLatin1String("vpn_tunnel");
const QString Context::REMOVED_ENCRYPT_DEVICES = QLatin1String("removed_encrypt_devices");

Context& Context::getDefaultContext()
{
	static Context defaultContext;
	return defaultContext;
}

QDataStream& operator<<(QDataStream& stream, const Context& ctx)
{
	stream << Context::serial_uid << ctx.attrs;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, Context& ctx)
{
	unsigned int local_serial_uid;

	stream >> local_serial_uid >> ctx.attrs;

	Q_ASSERT(Context::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}

bool userIdentifyEqual(const Context& c1, const Context& c2)
{
	if (!c1.hasAttribute(Context::USER_IDENTIFY))
		return false;
	if (!c2.hasAttribute(Context::USER_IDENTIFY))
		return false;

	const QString c1Id = c1.getAttribute(Context::USER_IDENTIFY).toString();
	const QString c2Id = c2.getAttribute(Context::USER_IDENTIFY).toString();
	return c1Id.compare(c2Id) == 0;
}

bool sessionIdentifyEqual(const Context& c1, const Context& c2)
{
	if (!c1.hasAttribute(Context::SESSION_IDENTIFY))
		return false;
	if (!c2.hasAttribute(Context::SESSION_IDENTIFY))
		return false;

	const QString c1Id = c1.getAttribute(Context::SESSION_IDENTIFY).toString();
	const QString c2Id = c2.getAttribute(Context::SESSION_IDENTIFY).toString();
	return c1Id.compare(c2Id) == 0;
}
