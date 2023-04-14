#include "vpn_config_manager_i_proxy.h"

VPNConfigManagerProxy::VPNConfigManagerProxy(const QString& uniqueIdentify, TcpConnection *connection)
	: Proxy(uniqueIdentify, connection)
{
}

bool VPNConfigManagerProxy::load(const QString& baseSavePath, const QByteArray& passphrase, bool loadCreds,
		const Context& ctx)
{
	QStringList params;
	params << baseSavePath << encodeToQString(passphrase)
		<< (loadCreds ? QLatin1String("true") : QLatin1String("false")) << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("load"), params, false);
	request.setConnection(connection);

	bool success = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			success = response->getResult() == QLatin1String("true") ? true : false;
		delete response;
	}

	return success;
}

void VPNConfigManagerProxy::unload(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("unload"), params, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

bool VPNConfigManagerProxy::backup(qint32 id, const QString& filename, VPNConfigManagerI::OptionFlag flag, const Context& ctx)
{
	QStringList params;
	params << QString::number(id) << filename << QString::number(flag) << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("backup"), params, false);
	request.setConnection(connection);

	bool success = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			success = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return success;
}

GenericResult VPNConfigManagerProxy::restore(const QString& filename, bool forceCover, const Context& ctx)
{
	QStringList params;
	params << filename << (forceCover ? QLatin1String("true") : QLatin1String("false")) << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("restore"), params, false);
	request.setConnection(connection);

	GenericResult result;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			result = decodeFromQString<GenericResult>(response->getResult());
		delete response;
	}

	return result;
}

qint32 VPNConfigManagerProxy::save(const VPNConfig& config, const QByteArray& passphrase,
		VPNConfigManagerI::OptionFlag flag, const Context& ctx)
{
	QStringList params;
	params << encodeToQString(config) << encodeToQString(passphrase)
		<< QString::number((int) flag) << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("save"), params, false);
	request.setConnection(connection);

	qint32 id = -1;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			id = response->getResult().toInt();
		delete response;
	}

	return id;
}

bool VPNConfigManagerProxy::remove(qint32 id, const Context& ctx)
{
	QStringList params;
	params << QString::number(id) << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("remove"), params, false);
	request.setConnection(connection);

	bool success = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			success = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return success;
}

bool VPNConfigManagerProxy::clearCredentials(qint32 id, const Context& ctx)
{
	QStringList params;
	params << QString::number(id) << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("clearCredentials"), params, false);
	request.setConnection(connection);

	bool success = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			success = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return success;
}

VPNConfig VPNConfigManagerProxy::get(qint32 id, const Context& ctx)
{
	QStringList params;
	params << QString::number(id) << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("get_by_id"), params, false);
	request.setConnection(connection);

	VPNConfig config;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			config = decodeFromQString<VPNConfig>(response->getResult());
		delete response;
	}

	return config;
}

VPNConfig VPNConfigManagerProxy::get(const QString& name, const Context& ctx)
{
	QStringList params;
	params << name << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("get_by_name"), params, false);
	request.setConnection(connection);

	VPNConfig config;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			config = decodeFromQString<VPNConfig>(response->getResult());
		delete response;
	}

	return config;
}

VPNConfig VPNConfigManagerProxy::get(const QString& host, quint16 port, const QString& protocol, const Context& ctx)
{
	QStringList params;
	params << host << QString::number(port) << protocol << encodeToQString(ctx);

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("get_by_host"), params, false);
	request.setConnection(connection);

	VPNConfig config;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			config = decodeFromQString<VPNConfig>(response->getResult());
		delete response;
	}

	return config;
}

QList<VPNConfig> VPNConfigManagerProxy::list(const Context& ctx) const
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNConfigManagerI"), uniqueIdentify, QLatin1String("list"), params, false);
	request.setConnection(connection);

	QList<VPNConfig> configList;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			configList = decodeFromQString< QList<VPNConfig> >(response->getResult());
		delete response;
	}

	return configList;
}
