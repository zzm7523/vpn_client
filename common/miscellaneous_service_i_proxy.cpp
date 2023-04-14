#include "miscellaneous_service_i_proxy.h"

MiscellaneousServiceProxy::MiscellaneousServiceProxy(const QString& uniqueIdentify, TcpConnection *connection)
	: Proxy(uniqueIdentify, connection)
{
}

bool MiscellaneousServiceProxy::changeLanguage(const QString& language, const Context& ctx)
{
	QStringList params;
	params << language << encodeToQString(ctx);

	Request request(QLatin1String("MiscellaneousServiceI"), uniqueIdentify, QLatin1String("changeLanguage"), params, false);
	request.setConnection(connection);

	bool switched = false;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			switched = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return switched;
}

QString MiscellaneousServiceProxy::generateFingerprint(const Context& ctx)
{
	QStringList params;
	params << encodeToQString(ctx);

	Request request(QLatin1String("MiscellaneousServiceI"), uniqueIdentify, QLatin1String("generateFingerprint"), params, false);
	request.setConnection(connection);

	QString fingerprint;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			fingerprint = response->getResult();
		delete response;
	}

	return fingerprint;
}

QString MiscellaneousServiceProxy::getFingerprint(const QString& fileName, const Context& ctx)
{
	QStringList params;
	params << fileName << encodeToQString(ctx);

	Request request(QLatin1String("MiscellaneousServiceI"), uniqueIdentify, QLatin1String("getFingerprint"), params, false);
	request.setConnection(connection);

	QString fingerprint;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			fingerprint = response->getResult();
		delete response;
	}

	return fingerprint;
}

void MiscellaneousServiceProxy::saveFingerprint(const QString& fileName, const QString& fingerprint, const Context& ctx)
{
	QStringList params;
	params << fileName << fingerprint << encodeToQString(ctx);

	Request request(QLatin1String("MiscellaneousServiceI"), uniqueIdentify, QLatin1String("saveFingerprint"), params, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

ExecuteResult MiscellaneousServiceProxy::execute(const QString& program, const QStringList& arguments,
		const QString& workingDirectory, const Context& ctx)
{
	QStringList params;
	params << program << encodeToQString(arguments) << workingDirectory << encodeToQString(ctx);

	Request request(QLatin1String("MiscellaneousServiceI"), uniqueIdentify, QLatin1String("execute"), params, false);
	request.setConnection(connection);

	ExecuteResult result;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			result = decodeFromQString<ExecuteResult>(response->getResult());
		delete response;
	}

	return result;
}
