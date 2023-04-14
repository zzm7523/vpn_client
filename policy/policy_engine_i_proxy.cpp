#include "policy_engine_i_proxy.h"

PolicyEngineProxy::PolicyEngineProxy(const QString& uniqueIdentify, TcpConnection *connection)
	: Proxy(uniqueIdentify, connection)
{
}

bool PolicyEngineProxy::initialize(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("PolicyEngineI"), uniqueIdentify, QLatin1String("initialize"), params, true);
	request.setConnection(connection);

	bool success;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			success = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return success;
}

void PolicyEngineProxy::clear(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("PolicyEngineI"), uniqueIdentify, QLatin1String("clear"), params, true);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

bool PolicyEngineProxy::addPolicy(const QString& policy, const Context& ctx)
{
	QStringList params;
	params << policy << encodeToQString(ctx);

	Request request(QLatin1String("PolicyEngineI"), uniqueIdentify, QLatin1String("addPolicy"), params, false);
	request.setConnection(connection);

	bool success;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			success = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return success;
}

bool PolicyEngineProxy::hasPolicy(PolicyEngineI::ApplyPoint point, const Context& ctx)
{
	QStringList params;
	params << QString::number(point) << encodeToQString(ctx);

	Request request(QLatin1String("PolicyEngineI"), uniqueIdentify, QLatin1String("hasPolicy"), params, false);
	request.setConnection(connection);

	bool success;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			success = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return success;
}

ApplyResult PolicyEngineProxy::applyPolicy(const QString& policy, const Context& ctx)
{
	QStringList params;
	params << policy << encodeToQString(ctx);

	Request request(QLatin1String("PolicyEngineI"), uniqueIdentify, QLatin1String("applyPolicy_by_policy"),
		params, false);
	request.setConnection(connection);

	ApplyResult applyResult;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			applyResult = decodeFromQString<ApplyResult>(response->getResult());
		delete response;
	}

	return applyResult;
}

ApplyResult PolicyEngineProxy::applyPolicy(PolicyEngineI::ApplyPoint point,
		const Context& ctx)
{
	QStringList params;
	params << QString::number(point) << encodeToQString(ctx);

	Request request(QLatin1String("PolicyEngineI"), uniqueIdentify, QLatin1String("applyPolicy_by_applyPoint"),
		params, false);
	request.setConnection(connection);

	ApplyResult applyResult;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			applyResult = decodeFromQString<ApplyResult>(response->getResult());
		delete response;
	}

	return applyResult;
}
