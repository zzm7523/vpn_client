#include "../policy/policy_engine_i.h"
#include "vpn_i_skeleton.h"

void VPNAgentSkeleton::processRequest(Request *request)
{
	TcpConnection *connection = request->getConnection();
	quint32 statusCode = Response::SUCCESS;
	QString reasonPhrase, result;

	if (request->getMethod() == QLatin1String("initialize")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 3);
		bool success = this->initialize(params.at(0), params.at(1), decodeFromQString<Context>(params.at(2)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("clear")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		this->clear(decodeFromQString<Context>(params.at(0)));

	} else if (request->getMethod() == QLatin1String("registerPolicyEngine")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		bool success = this->registerPolicyEngine(decodeFromQString<QHostAddress>(params.at(0)), params.at(1).toInt(), params.at(2),
			decodeFromQString<Context>(params.at(3)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("unregisterPolicyEngine")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		this->unregisterPolicyEngine(decodeFromQString<Context>(params.at(0)));

	} else if (request->getMethod() == QLatin1String("registerObserver")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		bool success = this->registerObserver(decodeFromQString<QHostAddress>(params.at(0)), params.at(1).toInt(), params.at(2),
			decodeFromQString<Context>(params.at(3)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("unregisterObserver")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		this->unregisterObserver(decodeFromQString<QHostAddress>(params.at(0)), params.at(1).toInt(), params.at(2),
			decodeFromQString<Context>(params.at(3)));

	} else if (request->getMethod() == QLatin1String("registerInputAgent")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		bool success = this->registerInputAgent(decodeFromQString<QHostAddress>(params.at(0)), params.at(1).toInt(), params.at(2),
			decodeFromQString<Context>(params.at(3)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("unregisterInputAgent")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		this->unregisterInputAgent(decodeFromQString<Context>(params.at(0)));

	} else if (request->getMethod() == QLatin1String("connect")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 3);
		this->connect(decodeFromQString<ServerEndpoint>(params.at(0)), decodeFromQString<QStringList>(params.at(1)),
			decodeFromQString<Context>(params.at(2)));
	} else if (request->getMethod() == QLatin1String("disconnect")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		this->disconnect(decodeFromQString<Context>(params.at(0)));

	} else {
		Q_ASSERT(false);
		statusCode = Response::LOCATE_METHOD_FAIL;
		reasonPhrase = QLatin1String("unkonwn function name ") + request->getMethod();
		qDebug() << "VPNAgentSkeleton::processRequest(...) fail" << reasonPhrase << "\n";
	}

	if (!request->isOneway()) {
		Response response(request->getRequestId(), statusCode, reasonPhrase, result);
		connection->sendResponse(&response);
	}
}

void VPNInputAgentSkeleton::processRequest(Request *request)
{
	TcpConnection *connection = request->getConnection();
	quint32 statusCode = Response::SUCCESS;
	QString reasonPhrase, result;

	if (request->getMethod() == QLatin1String("trustServerCertificate")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		VPNInputAgentI::TrustOption option = this->trustServerCertificate(decodeFromQString<QStringList>(params.at(0)),
			decodeFromQString<Context>(params.at(1)));
		result = VPNInputAgentI::Trust == option ? QLatin1String("trust") : QLatin1String("reject");
	} else if (request->getMethod() == QLatin1String("chooseClientCertificate")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		const QStringList& keyTypes = decodeFromQString<QStringList>(params.at(1));
		const QStringList& issuers = decodeFromQString<QStringList>(params.at(2));
		X509CertificateInfo certInfo =
			this->chooseClientCertificate(params.at(0), keyTypes, issuers, decodeFromQString<Context>(params.at(3)));
		result = encodeToQString<X509CertificateInfo>(certInfo);

	} else if (request->getMethod() == QLatin1String("getPrivateKeyPassword")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		QByteArray priKeyPass = this->getPrivateKeyPassword(decodeFromQString<Context>(params.at(0)));
		result = QLatin1String(priKeyPass.toBase64());
	} else if (request->getMethod() == QLatin1String("getPrivateKeyEncrypt")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		QByteArray ciphertext = this->getPrivateKeyEncrypt(params.at(0), decodeFromQString<Context>(params.at(1)));
		result = QLatin1String(ciphertext.toBase64());

	} else if (request->getMethod() == QLatin1String("getUserName")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = this->getUserName(decodeFromQString<Context>(params.at(0)));
	} else if (request->getMethod() == QLatin1String("getPassword")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = this->getPassword(decodeFromQString<Context>(params.at(0)));
	} else if (request->getMethod() == QLatin1String("getOtp")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = this->getOtp(decodeFromQString<Context>(params.at(0)));

	} else if (request->getMethod() == QLatin1String("getProxyUserName")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = this->getProxyUserName(decodeFromQString<Context>(params.at(0)));
	} else if (request->getMethod() == QLatin1String("getProxyPassword")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = this->getProxyPassword(decodeFromQString<Context>(params.at(0)));
	} else if (request->getMethod() == QLatin1String("isCanceled")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = this->isCanceled(decodeFromQString<Context>(params.at(0))) ? QLatin1String("true") : QLatin1String("false");
	} else {
		Q_ASSERT(false);
		statusCode = Response::LOCATE_METHOD_FAIL;
		reasonPhrase = QLatin1String("unkonwn function name ") + request->getMethod();
		qDebug() << "VPNInputAgentSkeleton::processRequest(...) fail" << reasonPhrase << "\n";
	}

	if (!request->isOneway()) {
		Response response(request->getRequestId(), statusCode, reasonPhrase, result);
		connection->sendResponse(&response);
	}
}

void VPNObserverSkeleton::processRequest(Request *request)
{
	TcpConnection *connection = request->getConnection();
	quint32 statusCode = Response::SUCCESS;
	QString reasonPhrase, result;

	if (request->getMethod() == QLatin1String("notify_warning")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 3);
		this->notify((VPNAgentI::Warning) params.at(0).toInt(), params.at(1), decodeFromQString<Context>(params.at(2)));
	} else if (request->getMethod() == QLatin1String("notify_error")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 3);
		this->notify((VPNAgentI::Error) params.at(0).toInt(), params.at(1), decodeFromQString<Context>(params.at(2)));
	} else if (request->getMethod() == QLatin1String("notify_state")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 3);
		this->notify((VPNAgentI::State) params.at(0).toInt(), decodeFromQString<VPNTunnel>(params.at(1)),
			decodeFromQString<Context>(params.at(2)));

	} else if (request->getMethod() == QLatin1String("notify_message")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		this->notify(params.at(0), decodeFromQString<Context>(params.at(1)));
	} else if (request->getMethod() == QLatin1String("notify_edge")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		this->notify(decodeFromQString<VPNEdge>(params.at(0)), decodeFromQString<Context>(params.at(1)));
	} else if (request->getMethod() == QLatin1String("notify_accessible_resources")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		this->notify(decodeFromQString<QList<AccessibleResource>>(params.at(0)), decodeFromQString<Context>(params.at(1)));
	} else if (request->getMethod() == QLatin1String("notify_stats")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		this->notify(decodeFromQString<VPNStatistics>(params.at(0)), decodeFromQString<Context>(params.at(1)));
	} else {
		Q_ASSERT(false);
		statusCode = Response::LOCATE_METHOD_FAIL;
		reasonPhrase = QLatin1String("unkonwn function name ") + request->getMethod();
		qDebug() << "VPNObserverSkeleton::processRequest(...) fail" << reasonPhrase << "\n";
	}

	if (!request->isOneway()) {
		Response response(request->getRequestId(), statusCode, reasonPhrase, result);
		connection->sendResponse(&response);
	}
}
