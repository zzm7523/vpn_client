#include "tapdriver_manager_i_proxy.h"

TapDriverManagerProxy::TapDriverManagerProxy(const QString& uniqueIdentify, TcpConnection *connection)
	: Proxy(uniqueIdentify, connection)
{
}

TapDriverManagerProxy::~TapDriverManagerProxy()
{
}

bool TapDriverManagerProxy::initialize(const QString& driverDir, const Context& ctx)
{
	QStringList params;
	params << driverDir << encodeToQString(ctx);

	Request request(QLatin1String("TapDriverManagerI"), uniqueIdentify, QLatin1String("initialize"), params, false);
	request.setConnection(connection);

	bool initialized = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			initialized = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return initialized;
}

void TapDriverManagerProxy::clear(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("TapDriverManagerI"), uniqueIdentify, QLatin1String("clear"), params, true);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response)
		delete response;
}

bool TapDriverManagerProxy::isTapDriverInstalled(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("TapDriverManagerI"), uniqueIdentify, QLatin1String("isTapDriverInstalled"), params, false);
	request.setConnection(connection);

	bool tapDrvInstalled = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			tapDrvInstalled = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return tapDrvInstalled;
}

int TapDriverManagerProxy::getTapDeviceCount(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("TapDriverManagerI"), uniqueIdentify, QLatin1String("getTapDeviceCount"), params, false);
	request.setConnection(connection);

	int tapDrvCount = -1;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			tapDrvCount = response->getResult().toInt();
		delete response;
	}

	return tapDrvCount;
}

bool TapDriverManagerProxy::installTapDriver(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("TapDriverManagerI"), uniqueIdentify, QLatin1String("installTapDriver"), params, false);
	request.setConnection(connection);

	bool installTapDrvSuccess = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			installTapDrvSuccess = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return installTapDrvSuccess;
}

bool TapDriverManagerProxy::removeTapDriver(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("TapDriverManagerI"), uniqueIdentify, QLatin1String("removeTapDriver"), params, false);
	request.setConnection(connection);

	bool remoteTapDrvSuccess = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			remoteTapDrvSuccess = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return remoteTapDrvSuccess;
}

