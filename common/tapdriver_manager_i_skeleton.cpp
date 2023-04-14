#include "tapdriver_manager_i_skeleton.h"

void TapDriverManagerSkeleton::processRequest(Request *request)
{
	TcpConnection *connection = request->getConnection();
	quint32 statusCode = Response::SUCCESS;
	QString reasonPhrase, result;

	if (request->getMethod() == QLatin1String("initialize")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		bool inited = this->initialize(params.at(0), decodeFromQString<Context>(params.at(1)));
		result = inited ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("clear")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		this->clear(decodeFromQString<Context>(params.at(0)));
		result = true;

	} else if (request->getMethod() == QLatin1String("isTapDriverInstalled")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		bool installed = this->isTapDriverInstalled(decodeFromQString<Context>(params.at(0)));
		result = installed ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("installTapDriver")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		bool success = this->installTapDriver(decodeFromQString<Context>(params.at(0)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("removeTapDriver")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		bool success = this->removeTapDriver(decodeFromQString<Context>(params.at(0)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("getTapDeviceCount")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		int count = this->getTapDeviceCount(decodeFromQString<Context>(params.at(0)));
		result = QString::number(count);
	} else {
		Q_ASSERT(false);
		statusCode = Response::LOCATE_METHOD_FAIL;
		reasonPhrase = QLatin1String("unkonwn function name ") + request->getMethod();
		qDebug() << "TapDriverManagerSkeleton::processRequest(...) fail" << reasonPhrase << "\n";
	}

	if (!request->isOneway()) {
		Response response(request->getRequestId(), statusCode, reasonPhrase, result);
		connection->sendResponse(&response);
	}
}
