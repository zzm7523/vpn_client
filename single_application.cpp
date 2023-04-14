#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QLocale>
#include <QDateTime>
#include <QTimer>
#include <QDir>
#include <QByteArray>
#include <QDebug>
#include <QProcess>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <Iphlpapi.h>
#include <ShlObj.h>
#include <Dbt.h>
#include <winioctl.h>
#include <setupapi.h>
#include <initguid.h>
#include <usbiodef.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

#include "common/common.h"
#include "common/message_box_util.h"
#include "common/passphrase_generator.h"
#include "common/file_util.h"
#include "common/encrypt_device_manager.h"
#include "common/vpn_config.h"
#include "common/vpn_config_manager_i_proxy.h"
#include "common/pkcs12_util.h"
#include "common/x509_certificate_util.h"

#include "single_application.h"
#include "preferences.h"
#include "vpn_item.h"
#include "settings.h"

#ifdef ENABLE_GUOMI
// 最后一次设备枚举时间(毫秒)
static qint64 lastDeviceEnumTime = 0L;

#ifdef _WIN32
DeviceInterfaceEventFilter::DeviceInterfaceEventFilter(HWND _hwnd)
	: hDeviceNotify(NULL)
{
	DEV_BROADCAST_DEVICEINTERFACE dbh;
	memset(&dbh, 0x0, sizeof(dbh));

	dbh.dbcc_size = sizeof(dbh);
	dbh.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	memcpy(&(dbh.dbcc_classguid), &(GUID_DEVINTERFACE_USB_DEVICE), sizeof(struct _GUID));

	DWORD flags = DEVICE_NOTIFY_WINDOW_HANDLE;
	hDeviceNotify = ::RegisterDeviceNotification(_hwnd, &dbh, flags);
	if (hDeviceNotify == NULL) {
		qDebug() << "RegisterDeviceNotification failed:" << GetLastError();
	}
}

DeviceInterfaceEventFilter::~DeviceInterfaceEventFilter()
{
	if (hDeviceNotify) {
		if (!UnregisterDeviceNotification(hDeviceNotify)) {
			qDebug() << "UnregisterDeviceNotification failed:" << GetLastError();
		}
		hDeviceNotify = NULL;
	}
}

// 正常情况下, 每次USBKEY插入应该只触发一次DBT_DEVICEARRIVAL事件
// !!windows10平台可能有bug, 每次USBKEY插入可能会触发如下事件流: DBT_DEVICEARRIVAL > DBT_DEVICEREMOVECOMPLETE > DBT_DEVICEARRIVAL
// 系统重启后, 回复正常
bool DeviceInterfaceEventFilter::nativeEventFilter(const QByteArray& eventType, void *message, long *result)
{
	Q_UNUSED(eventType); Q_UNUSED(result);

	const MSG *msg = static_cast<MSG*>(message);
	int msgType = msg->message;

	if (msgType == WM_DEVICECHANGE) {
		qint64 currentMSecsSinceEpoch = QDateTime::currentMSecsSinceEpoch();
		const PDEV_BROADCAST_HDR lpdb = (PDEV_BROADCAST_HDR) msg->lParam;

		switch(msg->wParam) {
		case DBT_DEVICEARRIVAL:
			// !!设备探测必须足够快; 只需关注DBT_DEVTYP_DEVICEINTERFACE就可以了!
			if (lpdb->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE /*|| lpdb->dbch_devicetype == DBT_DEVTYP_OEM ||
					lpdb->dbch_devicetype == DBT_DEVTYP_VOLUME || lpdb->dbch_devicetype == DBT_DEVTYP_PORT*/) {
				if (currentMSecsSinceEpoch - lastDeviceEnumTime > 1000) {
					lastDeviceEnumTime = currentMSecsSinceEpoch;
					// 重新探测加密设备提供者、重新枚举加密设备
					EncryptDeviceManager::instance()->enumDevice(DBT_DEVICE_ARRIVAL);
				}
			}
			break;
		case DBT_DEVICEREMOVECOMPLETE:
			if (lpdb->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE /*|| lpdb->dbch_devicetype == DBT_DEVTYP_OEM ||
					lpdb->dbch_devicetype == DBT_DEVTYP_VOLUME || lpdb->dbch_devicetype == DBT_DEVTYP_PORT*/) {
				if (currentMSecsSinceEpoch - lastDeviceEnumTime > 1000) {
					lastDeviceEnumTime = currentMSecsSinceEpoch;
					// 重新探测加密设备提供者、重新枚举加密设备
					EncryptDeviceManager::instance()->enumDevice(DBT_DEVICE_REMOVE);
				}
			}
			break;
		}

		// 应用程序的其它部分不需要处理这类消息
		return true;
	}

	return false;
}
#endif
#endif

SingleApplication::SingleApplication(int& argc, char *argv[])
	: QApplication(argc, argv), running(false), preferences(NULL), sharedMemory(NULL)
{
	// Register our custom types with Qt's Meta Object System.
	registerMetaTypes();

	// QApplication::applicationDirPath: Please instantiate the QApplication object first
	const QString appSavePath = FileUtil::getAppSavePath(QLatin1String(VPN_CONFIG_DIR_NAME));

#ifdef ENABLE_MINI_DUMP
	// MiniDump文件不能存储在AppDirPath目录(可能没有写权限), 可以存储在AppSavePath目录
	QString dumpFileName = QString(VPN_CLIENT).remove(".exe", Qt::CaseInsensitive);
	dumpFileName = QDir(appSavePath).absoluteFilePath(QString("%1_%2.dmp")
		.arg(dumpFileName).arg(QString::number(GetCurrentProcessId())));
	ProcessUtil::enableMiniDump(dumpFileName);
#endif

	Settings::instance()->load(QApplication::applicationDirPath(), appSavePath);

#ifdef ENABLE_GUOMI
	const QString libPath(QDir(QApplication::applicationDirPath()).absoluteFilePath(QLatin1String("lib")));
	const QString workDir(appSavePath);
	const QString lastProviderName = Settings::instance()->getLastProviderName();
	EncryptDeviceManager::instance()->initialize(libPath, workDir, lastProviderName);
#endif

	QString uniqueKey = SHARED_MEMORY_UNIQUE_KEY_PREFIX;
#ifdef WIN32
	// Nothing
#else
	uid_t uid = getuid();
	uniqueKey.append(QString::number(uid));	
#endif

	sharedMemory = new QSharedMemory(uniqueKey);
	if (!sharedMemory) {
		qDebug() << "Failed to create QSharedMemory object" << uniqueKey;
		QApplication::exit(1);
	}

#ifndef _WIN32
	// 释放共享内存(status == 0); VPN_CLIENT可能意外崩溃, 导致共享内存未释放
	if (sharedMemory->attach())
		sharedMemory->detach();
#endif

	if (!(running = sharedMemory->attach())) {	// attach data to shared memory.
		QByteArray byteArray("0"); // default value to note that no message is available.
		if (!sharedMemory->create(4096)) {
			qDebug() << "Unable to create single instance." << sharedMemory->errorString();
			QApplication::exit(1);
		}

		sharedMemory->lock();
		memcpy(sharedMemory->data(), byteArray.data(), qMin(sharedMemory->size(), byteArray.size()));
		sharedMemory->unlock();

		// start checking for messages of other instances.
		QTimer *timer = new QTimer(this);
		QObject::connect(timer, SIGNAL(timeout()), this, SLOT(checkForMessage()));
		timer->start(1000);
	}
}

SingleApplication::~SingleApplication()
{
	if (sharedMemory) {
		sharedMemory->detach();
		sharedMemory = NULL;
	}
}

void SingleApplication::setPreferences(Preferences *preferences)
{
	Q_ASSERT(preferences);
	this->preferences = preferences;
}

void SingleApplication::startTunnel()
{
	if (preferences)
		preferences->startTunnel();	
}

void SingleApplication::startTunnel(const QString& host, int port, const QString& protocol, const QString& ticket)
{
	if (preferences && !host.isEmpty() && port > 0 && !protocol.isEmpty()) {
		Ticket ticket_object;
		if (!ticket.isEmpty())
			ticket_object = Ticket::decode(ticket);
		preferences->startTunnel(host, port, protocol, ticket_object);
	}
}

void SingleApplication::stopTunnel(const QString& host, int port, const QString& protocol, bool silent)
{
	if (preferences && !host.isEmpty() && port > 0 && !protocol.isEmpty())
		preferences->stopTunnel(host, port, protocol, silent);
}

void SingleApplication::changeLanguage(const QString& language)
{
	if (language.compare(QLatin1String("zh_CN"), Qt::CaseInsensitive) == 0) {
		appTranslator.load(QLatin1String(":/vpn_client_zh_CN.qm"), QApplication::applicationDirPath());
		qtTranslator.load(QLatin1String(":/qt_zh_CN.qm"), QApplication::applicationDirPath());
		this->installTranslator(&appTranslator);
		this->installTranslator(&qtTranslator);
		Context::getDefaultContext().setAttribute(Context::LANG, Settings::instance()->getLanguage());
	} else {
		this->removeTranslator(&appTranslator);
		this->removeTranslator(&qtTranslator);
	}
}

int SingleApplication::exec()
{
#if defined(ENABLE_GUOMI) && defined(_WIN32)
	DeviceInterfaceEventFilter devItfEventFilter((HWND) preferences.winId());
	sapp.installNativeEventFilter(&devItfEventFilter);

	// 发送扫描加密设备事件
	QApplication::postEvent(&sapp, new QEvent(QEvent::Type(ENUM_ENCRYPT_DEVICE_EVENT)), Qt::LowEventPriority);
#endif

	processArguments(QCoreApplication::arguments(), true);

	return QApplication::exec();
}

void SingleApplication::checkForMessage()
{
	QByteArray byteArray;

	sharedMemory->lock();
	byteArray = QByteArray((const char*) sharedMemory->constData(), sharedMemory->size());
	sharedMemory->unlock();

	if (byteArray.left(1) != "0") {
		byteArray.remove(0, 1);
		emit messageAvailable(QString::fromUtf8(byteArray.constData()));

		byteArray = "0";	// remove message from shared memory.
		sharedMemory->lock();
		memcpy(sharedMemory->data(), byteArray.data(), qMin(sharedMemory->size(), byteArray.size()));
		sharedMemory->unlock();
	}
}

bool SingleApplication::isRunning() const
{
	return running;
}

bool SingleApplication::sendMessage(const QString& message)
{
	if (!running) {
		return false;
	} else {
		QByteArray byteArray("1");
		byteArray.append(message.toUtf8()).append('\0'); // < should be as char here, not a string!

		sharedMemory->lock();
		memcpy(sharedMemory->data(), byteArray.data(), qMin(sharedMemory->size(), byteArray.size()));
		sharedMemory->unlock();
		return true;
	}
}

void SingleApplication::receiveMessage(const QString& message)
{
	if (preferences) {
		preferences->showPreferences();
		processArguments(message.split(QRegularExpression(QLatin1String("\\s+")), QString::SkipEmptyParts), false);
	}
}

#ifdef ENABLE_GUOMI
bool SingleApplication::event(QEvent *e)
{
	if (e->type() == QEvent::Type(ENUM_ENCRYPT_DEVICE_EVENT)) {
		qint64 currentMSecsSinceEpoch = QDateTime::currentMSecsSinceEpoch();
		if (currentMSecsSinceEpoch - lastDeviceEnumTime > 1000) {
			lastDeviceEnumTime = currentMSecsSinceEpoch;
			EncryptDeviceManager::instance()->enumDevice(0);
		}
		e->accept();
		return true;

	} else {
		return QObject::event(e);
	}
}
#endif

void SingleApplication::processArguments(const QStringList& arguments, bool autoStart)
{
	QCommandLineParser parser;

	const QCommandLineOption hostOption("host", "Remote host name or ip address");
	parser.addOption(hostOption);
	const QCommandLineOption portOption("port", "TCP/UDP port");
	parser.addOption(portOption);
	const QCommandLineOption protocolOption("protocol", "Use protocol for communicating with peer");
	parser.addOption(protocolOption);

	const QCommandLineOption ticketOption("ticket", "User authentication ticket");
	parser.addOption(ticketOption);

	parser.addPositionalArgument("action", "Start or stop a tunnel.");

	if (!parser.parse(arguments)) {
		if (autoStart)
			this->startTunnel();
		return;
	}

	const QStringList args = parser.positionalArguments();
	if (args.isEmpty()) {
		if (autoStart)
			this->startTunnel();
		return;
	}

	const QString host = parser.value(hostOption);
	const QString port = parser.value(portOption);
	const QString protocol = parser.value(protocolOption);

	if (args.at(0).compare("start", Qt::CaseInsensitive)) {
		const QString ticket = parser.value(ticketOption);
		this->startTunnel(host, port.toInt(), protocol, ticket);
	} else if (args.at(0).compare("stop", Qt::CaseInsensitive)) {
		this->stopTunnel(host, port.toInt(), protocol, true);
	} else if (autoStart) {
		this->startTunnel();
	}
}

void SingleApplication::registerMetaTypes()
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

	qRegisterMetaType<VPNItem*>("VPNItem*");
}
