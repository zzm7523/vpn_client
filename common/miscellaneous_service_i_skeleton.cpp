#include "miscellaneous_service_i_skeleton.h"

void MiscellaneousServiceSkeleton::processRequest(Request *request)
{
	TcpConnection *connection = request->getConnection();
	quint32 statusCode = Response::SUCCESS;
	QString reasonPhrase, result;

	if (request->getMethod() == QLatin1String("changeLanguage")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		bool success = this->changeLanguage(params.at(0), decodeFromQString<Context>(params.at(1)));
		result = success ? QLatin1String("true") : QLatin1String("false");

	} else if (request->getMethod() == QLatin1String("generateFingerprint")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = this->generateFingerprint(decodeFromQString<Context>(params.at(0)));

	} else if (request->getMethod() == QLatin1String("getFingerprint")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		result = this->getFingerprint(params.at(0), decodeFromQString<Context>(params.at(1)));
	} else if (request->getMethod() == QLatin1String("saveFingerprint")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 3);
		this->saveFingerprint(params.at(0), params.at(1), decodeFromQString<Context>(params.at(2)));

	} else if (request->getMethod() == QLatin1String("execute")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		ExecuteResult executeResult = this->execute(params.at(0), decodeFromQString<QStringList>(params.at(1)),
				params.at(2), decodeFromQString<Context>(params.at(3)));
		result = encodeToQString(executeResult);

	} else {
		Q_ASSERT(false);
		statusCode = Response::LOCATE_METHOD_FAIL;
		reasonPhrase = QLatin1String("unkonwn function name ") + request->getMethod();
		qDebug() << "MiscellaneousServiceSkeleton::processRequest(...) fail" << reasonPhrase << "\n";
	}

	if (!request->isOneway()) {
		Response response(request->getRequestId(), statusCode, reasonPhrase, result);
		connection->sendResponse(&response);
	}
}
