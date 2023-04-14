#include "config/config.h"

#include <QApplication>
#include <QThread>
#include <QSystemTrayIcon>
#include <QTranslator>
#include <QSplashScreen>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QTimer>
#include <QDebug>
#include <QUuid>

#include "common/common.h"
#include "common/file_util.h"
#include "common/message_box_util.h"
#include "common/locator.h"
#include "common/request_dispatcher.h"
#include "common/system_info.h"
#include "common/vpn_i_proxy.h"
#include "common/tapdriver_manager_i_proxy.h"
#include "common/vpn_config.h"
#include "common/vpn_config_manager_i_proxy.h"
#include "common/encrypt_device_manager.h"

#include "preferences.h"
#include "settings.h"
#include "single_application.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef ENABLE_GUOMI
#include <openssl/encrypt_device.h>
#endif

static void clearAndExit(int exit_code)
{
	ERR_free_strings();
	EVP_cleanup();
	exit(exit_code);
}

#ifdef _WIN32
static void waitForWin32ServiceStart(QSplashScreen *splash, int timeout = 5000)
{
	do {
		SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	    if (hSCM) {
			bool waitOn = true;
			SC_HANDLE hService = OpenService(hSCM, TEXT(VPN_SERVICE_NAME), SERVICE_QUERY_STATUS);

			if (hService) {
				SERVICE_STATUS info;
				int res = QueryServiceStatus(hService, &info);	// 查询服务状态

				if (res)
					waitOn = info.dwCurrentState != SERVICE_RUNNING;
				CloseServiceHandle(hService);
			} else {
				qDebug() << VPN_SERVICE << "is not install";
				waitOn = false;	// 服务未安装
			}

			CloseServiceHandle(hSCM);
			if (!waitOn)
				break;
		}

		if (ProcessUtil::findProcess(VPN_SERVICE) != 0) {	// 处于调试模式, 控制台允许
			qDebug() << VPN_SERVICE << "is running";
			break;
		}

		if (splash) {
			splash->show();
			splash->showMessage(QApplication::tr("Wait service start"));
			QApplication::instance()->processEvents();
		}

		QThread::msleep(500);	// 等候500毫秒(系统很忙, 等候的时间长一些)再进行下一次查询

	} while ((timeout -= 500) > 0);
}
#endif

int main (int argc, char *argv[])
{
	QApplication::setAttribute(Qt::AA_EnableHighDpiScaling, true);
	QApplication::setQuitOnLastWindowClosed(false);

	Q_INIT_RESOURCE(vpn_client);	// 确保资源被加载, Q_INIT_RESOURCE(...)需要在main函数中调用

	OpenSSL_add_all_algorithms();
#ifdef ENABLE_GUOMI
	ECDSA_set_default_method(ECDSA_sm2());
#endif

	SingleApplication sapp(argc, argv);
	if (sapp.isRunning()) {
		QString message;
		for (int i = 1; i < argc; ++i)	// 命令行转换成消息, 不包括程序名
			message.append(QLatin1String(argv[i])).append(QLatin1Char(' '));
		sapp.sendMessage(message.trimmed());
		clearAndExit(0);
	} else
		sapp.changeLanguage(Settings::instance()->getLanguage());

	QObject::connect(&sapp, SIGNAL(messageAvailable(const QString&)), &sapp, SLOT(receiveMessage(const QString&)));

	// 轻量化vpn_client, 去掉QSplashScreen

	// 等候VPNService启动完成, 最多等候5秒, 太长影响用户体验
#ifdef _WIN32
#ifndef _DEBUG
	waitForWin32ServiceStart(NULL, 5000);
#endif
#endif

	// 获取当前用户名
	const QString currentUser = SystemInfo::getCurrentUser();
	Q_ASSERT(!currentUser.isEmpty());
	Context::getDefaultContext().setAttribute(Context::USER_IDENTIFY, currentUser);

	// 设置唯一Session标识
	const QString sessionIdentify = QUuid::createUuid().toString();
	Context::getDefaultContext().setAttribute(Context::SESSION_IDENTIFY, sessionIdentify);

	// 用户可能启动多个不同的前台程序(GUI, BROWSER ...)，用currentUser而不是sessionIdentify标识后台服务

	try {
		// 定位VPNConfigManagerI
		VPNConfigManagerProxy *configMgrI = Locator::locate<VPNConfigManagerProxy>(VPN_LOCAL_HOST, VPN_SERVICE_PORT,
			QString("VPNConfigManagerI:%1").arg(currentUser));
		if (!configMgrI) {
			MessageBoxUtil::error(NULL, VPN_CLIENT_VER_PRODUCTNAME_STR,
				QApplication::translate("Locator", "Don't locate vpn config manager, \nplease restart service"));
			clearAndExit(1);
		}

		TapDriverManagerProxy *tapDrvMgrI = NULL;
#ifdef _WIN32
		// 定位TapDriverManagerI
		tapDrvMgrI = Locator::locate<TapDriverManagerProxy>(VPN_LOCAL_HOST, VPN_SERVICE_PORT,
			QString("TapDriverManagerI:%1").arg(currentUser));
		if (tapDrvMgrI) {
			tapDrvMgrI->initialize(QString(QLatin1String("%1/driver")).arg(QApplication::applicationDirPath()));
		} else {
			MessageBoxUtil::error(NULL, VPN_CLIENT_VER_PRODUCTNAME_STR,
				QApplication::translate("Locator", "Don't locate tap driver manager, \nplease restart service"));
			clearAndExit(1);
		}
#endif

		// 定位MiscellaneousServiceI
		MiscellaneousServiceProxy *miscSrvI = Locator::locate<MiscellaneousServiceProxy>(VPN_LOCAL_HOST, VPN_SERVICE_PORT,
			QString("MiscellaneousServiceI:%1").arg(currentUser));
		if (miscSrvI) {
			miscSrvI->changeLanguage(Settings::instance()->getLanguage());
		} else {
			MessageBoxUtil::error(NULL, VPN_CLIENT_VER_PRODUCTNAME_STR,
				QApplication::translate("Locator", "Don't locate miscellaneous service, \nplease restart service"));
			clearAndExit(1);
		}

		Preferences preferences(configMgrI, tapDrvMgrI, miscSrvI);
		sapp.setPreferences(&preferences);
		sapp.processEvents();	// 不要在sapp.setPreferences(...)调用前

		preferences.show();
		sapp.exec();

	} catch (const SocketException& ex) {
		Q_UNUSED(ex);
		MessageBoxUtil::error(NULL, VPN_CLIENT_VER_PRODUCTNAME_STR,
			QApplication::translate("Communicator", "Service communicate exception, \nplease restart service"));
		clearAndExit(1);
	}

	// 不要直接调用clearAndExit(...)退出; 因为它调用exit(...), 导致一些清理函数不会执行
	ERR_free_strings();
	EVP_cleanup();
	return 0;
}
