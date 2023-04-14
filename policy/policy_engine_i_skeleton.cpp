#include "policy_engine_i_skeleton.h"

void PolicyEngineSkeleton::processRequest(Request *request)
{
	TcpConnection *connection = request->getConnection();
	quint32 statusCode = Response::SUCCESS;
	QString reasonPhrase, result;

	if (request->getMethod() == QLatin1String("initialize")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		bool success = this->initialize(decodeFromQString<Context>(params.at(0)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("clear")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		this->clear(decodeFromQString<Context>(params.at(0)));

	} else if (request->getMethod() == QLatin1String("addPolicy")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		bool success = this->addPolicy(params.at(0), decodeFromQString<Context>(params.at(1)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("hasPolicy")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		PolicyEngineI::ApplyPoint point = (PolicyEngineI::ApplyPoint) params.at(0).toInt();
		bool success = this->hasPolicy(point, decodeFromQString<Context>(params.at(1)));
		result = success ? QLatin1String("true") : QLatin1String("false");

	} else if (request->getMethod() == QLatin1String("applyPolicy_by_policy")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		ApplyResult applyResult = this->applyPolicy(params.at(0), decodeFromQString<Context>(params.at(1)));
		result = encodeToQString(applyResult);
	} else if (request->getMethod() == QLatin1String("applyPolicy_by_applyPoint")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		PolicyEngineI::ApplyPoint point = (PolicyEngineI::ApplyPoint) params.at(0).toInt();
		ApplyResult applyResult = this->applyPolicy(point, decodeFromQString<Context>(params.at(1)));
		result = encodeToQString(applyResult);

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
