#include "vpn_config_manager_i_skeleton.h"

void VPNConfigManagerSkeleton::processRequest(Request *request)
{
	TcpConnection *connection = request->getConnection();
	quint32 statusCode = Response::SUCCESS;
	QString reasonPhrase, result;

	if (request->getMethod() == QLatin1String("load")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		bool loadCreds = params.at(2) == QLatin1String("true");
		bool success = this->load(params.at(0), decodeFromQString<QByteArray>(params.at(1)), loadCreds,
			decodeFromQString<Context>(params.at(3)));
		result = success ? QLatin1String("true") : QLatin1String("false");
	} else if (request->getMethod() == QLatin1String("unload")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		this->unload(decodeFromQString<Context>(params.at(0)));

	} else if (request->getMethod() == QLatin1String("backup")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		VPNConfigManagerI::OptionFlag flag = static_cast<VPNConfigManagerI::OptionFlag>( params.at(2).toInt());
		bool success = this->backup(params.at(0).toInt(), params.at(1), flag, decodeFromQString<Context>(params.at(3)));
		result = success ? QLatin1String("true") : QLatin1String("false");

	} else if (request->getMethod() == QLatin1String("restore")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 3);
		bool forceCover = params.at(1) == QLatin1String("true");
		result = encodeToQString(this->restore(params.at(0), forceCover, decodeFromQString<Context>(params.at(2))));

	} else if (request->getMethod() == QLatin1String("save")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		VPNConfigManagerI::OptionFlag flag = (VPNConfigManagerI::OptionFlag) params.at(2).toInt();
		qint32 id = this->save(decodeFromQString<VPNConfig>(params.at(0)),
			decodeFromQString<QByteArray>(params.at(1)), flag,
			decodeFromQString<Context>(params.at(3)));
		result = QString::number(id);
	} else if (request->getMethod() == QLatin1String("remove")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		bool success = this->remove(params.at(0).toUInt(), decodeFromQString<Context>(params.at(1)));
		result = success ? QLatin1String("true") : QLatin1String("false");

	} else if (request->getMethod() == QLatin1String("clearCredentials")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		bool success = this->clearCredentials(params.at(0).toUInt(), decodeFromQString<Context>(params.at(1)));
		result = success ? QLatin1String("true") : QLatin1String("false");

	} else if (request->getMethod() == QLatin1String("get_by_id")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		result = encodeToQString(this->get(params.at(0).toInt(), decodeFromQString<Context>(params.at(1))));
	} else if (request->getMethod() == QLatin1String("get_by_name")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 2);
		result = encodeToQString(this->get(params.at(0), decodeFromQString<Context>(params.at(1))));
	} else if (request->getMethod() == QLatin1String("get_by_host")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 4);
		result = encodeToQString(this->get(params.at(0), params.at(1).toUShort(), params.at(2),
			decodeFromQString<Context>(params.at(3)))); 
		
	} else if (request->getMethod() == QLatin1String("list")) {
		const QStringList& params = request->getParams();
		Q_ASSERT(params.size() == 1);
		result = encodeToQString(this->list(decodeFromQString<Context>(params.at(0))));
	} else {
		Q_ASSERT(false);
		statusCode = Response::LOCATE_METHOD_FAIL;
		reasonPhrase = QLatin1String("unkonwn function name ") + request->getMethod();
		qDebug() << "VPNConfigManagerSkeleton::processRequest(...) fail" << reasonPhrase << "\n";
	}

	if (!request->isOneway()) {
		Response response(request->getRequestId(), statusCode, reasonPhrase, result);
		connection->sendResponse(&response);
	}
}
