#include "../common/common.h"
#include "../common/file_util.h"
#include "../common/request_dispatcher.h"
#include "../common/locator.h"
#include "../policy/policy_engine_servant.h"

#include "service.h"
#include "vpn_agent_servant.h"
#include "vpn_config_manager_servant.h"
#include "tapdriver_manager_servant.h"
#include "miscellaneous_service_servant.h"

Service::Service(int argc, char **argv)
	: QtService<QCoreApplication>(argc, argv, QLatin1String(VPN_SERVICE_NAME))
{
#ifdef ENABLE_MINI_DUMP
	// MiniDump文件不能存储在AppDirPath目录(可能没有写权限), 可以存储在AppSavePath目录
	const QString appSavePath = FileUtil::getAppSavePath(QLatin1String(VPN_CONFIG_DIR_NAME));
	const QString baseName = QString(VPN_SERVICE).remove(".exe", Qt::CaseInsensitive);
	const QString dumpFileName = QDir(appSavePath).absoluteFilePath(QString("%1_%2.dmp")
		.arg(baseName).arg(QString::number(GetCurrentProcessId())));
	ProcessUtil::enableMiniDump(dumpFileName);
#endif

	setServiceDescription(QLatin1String(VPN_SERVICE_DESCRIPTION));
	setStartupType(QtServiceController::AutoStartup);
	setServiceFlags(QtServiceBase::CanBeSuspended);
	// Register our custom types with Qt's Meta Object System.
	registerMetaTypes();
}

Service::~Service() {
}

void Service::incomingConnection(qintptr socketDescriptor)
{
	// create a new connection object and append it to the connection list
	qDebug() << "New client connection";
	TcpConnection *connection = new TcpConnection();
	connection->setSocketDescriptor(socketDescriptor);

	// rigister TcpConnection
	Locator::registerConnection(connection);
}

void Service::start()
{
	qDebug() << "Starting service on port " << VPN_SERVICE_PORT;

	if (this->listen(VPN_LOCAL_HOST, VPN_SERVICE_PORT)) {
		// register VPNConfigManagerI Servant
		SkeletonFactory *configMgrSrvFaImpl = new GeneralSkeletonFactory<VPNConfigManagerServant>();
		RequestDispatcher::registerFactory(QLatin1String("VPNConfigManagerI"), configMgrSrvFaImpl);

#ifdef _WIN32
		// register TapDriverManagerAgentI Servant
		SkeletonFactory *tapMgrSrvFaImpl = new GeneralSkeletonFactory<TapDriverManagerServant>();
		RequestDispatcher::registerFactory(QLatin1String("TapDriverManagerI"), tapMgrSrvFaImpl);
#endif

		// register MiscellaneousServiceI Servant
		SkeletonFactory *miscMgrSrvFaImpl = new GeneralSkeletonFactory<MiscellaneousServiceServant>();
		RequestDispatcher::registerFactory(QLatin1String("MiscellaneousServiceI"), miscMgrSrvFaImpl);

		// register VPNAgentI Servant
		SkeletonFactory *vpnAgentSrvFaImpl = new GeneralSkeletonFactory<VPNAgentServant>();
		RequestDispatcher::registerFactory(QLatin1String("VPNAgentI"), vpnAgentSrvFaImpl);

		qDebug() << "Service seems started succesfully";
		logMessage(QLatin1String("Service seems started succesfully"), QtServiceBase::Success);
	} else {
		const QString message = QString(QLatin1String("Service listen port %1 fail")).arg(VPN_SERVICE_PORT);
		qDebug() << message;
		logMessage(message, QtServiceBase::Error);
		QCoreApplication::exit(1);
	}
}

void Service::stop()
{
	Locator::unregisterAllConnections();
}

void Service::registerMetaTypes()
{
	// Register our custom types with Qt's Meta Object System.
	qRegisterMetaType<VPNAgentI::State>("VPNAgentI::State");
	qRegisterMetaType<VPNAgentI::Warning>("VPNAgentI::Warning");
	qRegisterMetaType<VPNAgentI::State>("VPNAgentI::Error");

	qRegisterMetaType<Context>("Context");
	qRegisterMetaTypeStreamOperators<Context>("Context");

	qRegisterMetaType<GenericResult>("GenericResult");
	qRegisterMetaTypeStreamOperators<GenericResult>("GenericResult");

	qRegisterMetaType<X509CertificateInfo>("X509CertificateInfo");
	qRegisterMetaTypeStreamOperators<X509CertificateInfo>("X509CertificateInfo");

	qRegisterMetaType<Credentials>("Credentials");
	qRegisterMetaTypeStreamOperators<Credentials>("Credentials");

	qRegisterMetaType<AccessibleResource>("AccessibleResource");
	qRegisterMetaTypeStreamOperators<AccessibleResource>("AccessibleResource");

	qRegisterMetaType<ServerEndpoint>("ServerEndpoint");
	qRegisterMetaTypeStreamOperators<ServerEndpoint>("ServerEndpoint");

	qRegisterMetaType<VPNConfig>("VPNConfig");
	qRegisterMetaTypeStreamOperators<VPNConfig>("VPNConfig");

	qRegisterMetaType<TLSAuth>("TLSAuth");
	qRegisterMetaTypeStreamOperators<TLSAuth>("TLSAuth");

	qRegisterMetaType<VPNEdge>("VPNEdge");
	qRegisterMetaTypeStreamOperators<VPNEdge>("VPNEdge");

	qRegisterMetaType<VPNTunnel>("VPNTunnel");
	qRegisterMetaTypeStreamOperators<VPNTunnel>("VPNTunnel");

	qRegisterMetaType<VPNStatistics>("VPNStatistics");
	qRegisterMetaTypeStreamOperators<VPNStatistics>("VPNStatistics");
}
