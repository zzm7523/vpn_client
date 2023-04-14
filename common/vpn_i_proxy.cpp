#include "../policy/policy_engine_i.h"
#include "vpn_i_proxy.h"

#include <QEventLoop>
#include <QTimer>

VPNAgentProxy::VPNAgentProxy(const QString& uniqueIdentify, TcpConnection *connection)
	: Proxy(uniqueIdentify, connection)
{
}

bool VPNAgentProxy::initialize(const QString& configDirectory, const QString& workingDirectory, const Context& ctx)
{
	QStringList params;
	params << configDirectory << workingDirectory << encodeToQString(ctx);

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("initialize"), params, false);
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

void VPNAgentProxy::clear(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("clear"), params, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

bool VPNAgentProxy::registerPolicyEngine(const QHostAddress& hostAddress, quint16 port, const QString& engineUniqueIdentify,
		const Context& ctx)
{
	QStringList params;
	params << encodeToQString(hostAddress) << QString::number(port) << engineUniqueIdentify << encodeToQString(ctx);

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("registerPolicyEngine"), params, false);
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

void VPNAgentProxy::unregisterPolicyEngine(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("unregisterPolicyEngine"), params, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

bool VPNAgentProxy::registerObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx)
{
	QStringList params;
	params << encodeToQString(hostAddress) << QString::number(port) << observerUniqueIdentify << encodeToQString(ctx);

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("registerObserver"), params, false);
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

void VPNAgentProxy::unregisterObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx)
{
	QStringList params;
	params << encodeToQString(hostAddress) << QString::number(port) << observerUniqueIdentify << encodeToQString(ctx);

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("unregisterObserver"), params, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

bool VPNAgentProxy::registerInputAgent(const QHostAddress& hostAddress, quint16 port, const QString& inputAgentUniqueIdentify,
		const Context& ctx)
{
	QStringList params;
	params << encodeToQString(hostAddress) << QString::number(port) << inputAgentUniqueIdentify << encodeToQString(ctx);

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("registerInputAgent"), params, false);
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

void VPNAgentProxy::unregisterInputAgent(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("unregisterInputAgent"), params, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

void VPNAgentProxy::connect(const ServerEndpoint& remote, const QStringList& params, const Context& ctx)
{
	QStringList requestParams;
	requestParams << encodeToQString(remote) << encodeToQString(params) << encodeToQString(ctx);

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("connect"), requestParams, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

void VPNAgentProxy::disconnect(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNAgentI"), uniqueIdentify, QLatin1String("disconnect"), params, false);
	request.setConnection(connection);

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		delete response;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

VPNInputAgentProxy::VPNInputAgentProxy(const QString& uniqueIdentify, TcpConnection *connection)
	: Proxy(uniqueIdentify, connection)
{
}

VPNInputAgentProxy::TrustOption VPNInputAgentProxy::trustServerCertificate(const QStringList& x509Chain, const Context& ctx)
{
	QStringList params;
	params << encodeToQString(x509Chain) << encodeToQString(ctx);

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("trustServerCertificate"), params, false);
	request.setConnection(connection);

	VPNInputAgentProxy::TrustOption option = VPNInputAgentProxy::Reject;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			option = response->getResult() == QLatin1String("trust") ? VPNInputAgentProxy::Trust : VPNInputAgentProxy::Reject;
		delete response;
	}

	return option;
}

X509CertificateInfo VPNInputAgentProxy::chooseClientCertificate(const QString& tlsVersion, const QStringList& keyTypes,
		const QStringList& issuers, const Context& ctx)
{
	QStringList params;
	params << tlsVersion << encodeToQString(keyTypes) << encodeToQString(issuers) << encodeToQString(ctx);
	
	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("chooseClientCertificate"), params, false);
	request.setConnection(connection);

	QString certInfo;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			certInfo = response->getResult();
		delete response;
	}

	return decodeFromQString<X509CertificateInfo>(certInfo);
}

QByteArray VPNInputAgentProxy::getPrivateKeyPassword(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("getPrivateKeyPassword"), params, false);
	request.setConnection(connection);

	QString privateKeyPassword;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			privateKeyPassword = response->getResult();
		delete response;
	}

	return QByteArray::fromBase64(privateKeyPassword.toLocal8Bit());
}

QByteArray VPNInputAgentProxy::getPrivateKeyEncrypt(const QString& plaintext, const Context& ctx)
{
	QStringList params;
	params << plaintext << encodeToQString(ctx);

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("getPrivateKeyEncrypt"), params, false);
	request.setConnection(connection);

	QString ciphertext;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			ciphertext = response->getResult();
		delete response;
	}

	return QByteArray::fromBase64(ciphertext.toLocal8Bit());
}

QString VPNInputAgentProxy::getUserName(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("getUserName"), params, false);
	request.setConnection(connection);

	QString userName;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			userName = response->getResult();
		delete response;
	}

	return userName;
}

QString VPNInputAgentProxy::getPassword(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("getPassword"), params, false);
	request.setConnection(connection);

	QString password;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			password = response->getResult();
		delete response;
	}

	return password;
}

QString VPNInputAgentProxy::getOtp(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("getOtp"), params, false);
	request.setConnection(connection);

	QString otp;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			otp = response->getResult();
		delete response;
	}

	return otp;
}

QString VPNInputAgentProxy::getProxyUserName(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("getProxyUserName"), params, false);
	request.setConnection(connection);

	QString proxyUserName;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			proxyUserName = response->getResult();
		delete response;
	}

	return proxyUserName;
}

QString VPNInputAgentProxy::getProxyPassword(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("getProxyPassword"), params, false);
	request.setConnection(connection);

	QString proxyPassword;

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			proxyPassword = response->getResult();
		delete response;
	}

	return proxyPassword;
}

bool VPNInputAgentProxy::isCanceled(const Context& ctx)
{
	QStringList params(encodeToQString(ctx));

	Request request(QLatin1String("VPNInputAgentI"), uniqueIdentify, QLatin1String("isCanceled"), params, false);
	request.setConnection(connection);

	bool canceled = true;	// 缺省等于true更合适

	Invoke invoke;
	Response *response = invoke.invoke(&request);
	if (response) {
		if (Response::SUCCESS == response->getStatusCode())
			canceled = response->getResult().toLower() == QLatin1String("true") ? true : false;
		delete response;
	}

	return canceled;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

VPNObserverProxy::VPNObserverProxy(const QString& uniqueIdentify, TcpConnection *connection)
	: Proxy(uniqueIdentify, connection)
{
}

void VPNObserverProxy::notify(VPNAgentI::Warning warning, const QString& reason, const Context& ctx)
{
	QStringList params;
	params << QString::number(static_cast<quint32>(warning)) << reason << encodeToQString(ctx);

	// 单向就可以了
	Request request(QLatin1String("VPNObserverI"), uniqueIdentify, QLatin1String("notify_warning"), params, true);
	request.setConnection(connection);
	doNotify(&request);
}

void VPNObserverProxy::notify(VPNAgentI::Error error, const QString& reason, const Context& ctx)
{
	QStringList params;
	params << QString::number(static_cast<quint32>(error)) << reason << encodeToQString(ctx);

	// 单向就可以了
	Request request(QLatin1String("VPNObserverI"), uniqueIdentify, QLatin1String("notify_error"), params, true);
	request.setConnection(connection);
	doNotify(&request);
}

void VPNObserverProxy::notify(VPNAgentI::State state, const VPNTunnel& tunnel, const Context& ctx)
{
	QStringList params;
	params << QString::number(static_cast<quint32>(state)) << encodeToQString(tunnel) << encodeToQString(ctx);

	// 单向就可以了
	Request request(QLatin1String("VPNObserverI"), uniqueIdentify, QLatin1String("notify_state"), params, true);
	request.setConnection(connection);
	doNotify(&request);
}

void VPNObserverProxy::notify(const QString& message, const Context& ctx)
{
	QStringList params;
	params << message << encodeToQString(ctx);

	// 单向就可以了
	Request request(QLatin1String("VPNObserverI"), uniqueIdentify, QLatin1String("notify_message"), params, true);
	request.setConnection(connection);
	doNotify(&request);
}

void VPNObserverProxy::notify(const VPNEdge& edge, const Context& ctx)
{
	QStringList params;
	params << encodeToQString(edge) << encodeToQString(ctx);

	// 单向就可以了
	Request request(QLatin1String("VPNObserverI"), uniqueIdentify, QLatin1String("notify_edge"), params, true);
	request.setConnection(connection);
	doNotify(&request);
}

void VPNObserverProxy::notify(const QList<AccessibleResource>& accessibleResources, const Context& ctx)
{
	QStringList params;
	params << encodeToQString(accessibleResources) << encodeToQString(ctx);

	// 单向就可以了
	Request request(QLatin1String("VPNObserverI"), uniqueIdentify, QLatin1String("notify_accessible_resources"), params, true);
	request.setConnection(connection);
	doNotify(&request);
}

void VPNObserverProxy::notify(const VPNStatistics& statistics, const Context& ctx)
{
	QStringList params;
	params << encodeToQString(statistics) << encodeToQString(ctx);

	// !! 频繁发生, 提升性能, statistics 单向就可以了
	Request request(QLatin1String("VPNObserverI"), uniqueIdentify, QLatin1String("notify_stats"), params, true);
	request.setConnection(connection);
	doNotify(&request);
}

void VPNObserverProxy::doNotify(Request *request)
{
	Invoke invoke;

	try {
		Response *response = invoke.invoke(request);
		if (response) {
			delete response;
		}
	} catch (const SocketException& ex) {
		// 忽略SocketException异常, 客户端可能异常终止
		qDebug() << "VPNAgentServant::notify_1(...), " << ex.getMessage();
	}
}
