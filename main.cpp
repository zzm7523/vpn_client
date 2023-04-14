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
				int res = QueryServiceStatus(hService, &info);	// ��ѯ����״̬

				if (res)
					waitOn = info.dwCurrentState != SERVICE_RUNNING;
				CloseServiceHandle(hService);
			} else {
				qDebug() << VPN_SERVICE << "is not install";
				waitOn = false;	// ����δ��װ
			}

			CloseServiceHandle(hSCM);
			if (!waitOn)
				break;
		}

		if (ProcessUtil::findProcess(VPN_SERVICE) != 0) {	// ���ڵ���ģʽ, ����̨����
			qDebug() << VPN_SERVICE << "is running";
			break;
		}

		if (splash) {
			splash->show();
			splash->showMessage(QApplication::tr("Wait service start"));
			QApplication::instance()->processEvents();
		}

		QThread::msleep(500);	// �Ⱥ�500����(ϵͳ��æ, �Ⱥ��ʱ�䳤һЩ)�ٽ�����һ�β�ѯ

	} while ((timeout -= 500) > 0);
}
#endif

int main (int argc, char *argv[])
{
	QApplication::setAttribute(Qt::AA_EnableHighDpiScaling, true);
	QApplication::setQuitOnLastWindowClosed(false);

	Q_INIT_RESOURCE(vpn_client);	// ȷ����Դ������, Q_INIT_RESOURCE(...)��Ҫ��main�����е���

	OpenSSL_add_all_algorithms();
#ifdef ENABLE_GUOMI
	ECDSA_set_default_method(ECDSA_sm2());
#endif

	SingleApplication sapp(argc, argv);
	if (sapp.isRunning()) {
		QString message;
		for (int i = 1; i < argc; ++i)	// ������ת������Ϣ, ������������
			message.append(QLatin1String(argv[i])).append(QLatin1Char(' '));
		sapp.sendMessage(message.trimmed());
		clearAndExit(0);
	} else
		sapp.changeLanguage(Settings::instance()->getLanguage());

	QObject::connect(&sapp, SIGNAL(messageAvailable(const QString&)), &sapp, SLOT(receiveMessage(const QString&)));

	// ������vpn_client, ȥ��QSplashScreen

	// �Ⱥ�VPNService�������, ���Ⱥ�5��, ̫��Ӱ���û�����
#ifdef _WIN32
#ifndef _DEBUG
	waitForWin32ServiceStart(NULL, 5000);
#endif
#endif

	// ��ȡ��ǰ�û���
	const QString currentUser = SystemInfo::getCurrentUser();
	Q_ASSERT(!currentUser.isEmpty());
	Context::getDefaultContext().setAttribute(Context::USER_IDENTIFY, currentUser);

	// ����ΨһSession��ʶ
	const QString sessionIdentify = QUuid::createUuid().toString();
	Context::getDefaultContext().setAttribute(Context::SESSION_IDENTIFY, sessionIdentify);

	// �û��������������ͬ��ǰ̨����(GUI, BROWSER ...)����currentUser������sessionIdentify��ʶ��̨����

	try {
		// ��λVPNConfigManagerI
		VPNConfigManagerProxy *configMgrI = Locator::locate<VPNConfigManagerProxy>(VPN_LOCAL_HOST, VPN_SERVICE_PORT,
			QString("VPNConfigManagerI:%1").arg(currentUser));
		if (!configMgrI) {
			MessageBoxUtil::error(NULL, VPN_CLIENT_VER_PRODUCTNAME_STR,
				QApplication::translate("Locator", "Don't locate vpn config manager, \nplease restart service"));
			clearAndExit(1);
		}

		TapDriverManagerProxy *tapDrvMgrI = NULL;
#ifdef _WIN32
		// ��λTapDriverManagerI
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

		// ��λMiscellaneousServiceI
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
		sapp.processEvents();	// ��Ҫ��sapp.setPreferences(...)����ǰ

		preferences.show();
		sapp.exec();

	} catch (const SocketException& ex) {
		Q_UNUSED(ex);
		MessageBoxUtil::error(NULL, VPN_CLIENT_VER_PRODUCTNAME_STR,
			QApplication::translate("Communicator", "Service communicate exception, \nplease restart service"));
		clearAndExit(1);
	}

	// ��Ҫֱ�ӵ���clearAndExit(...)�˳�; ��Ϊ������exit(...), ����һЩ����������ִ��
	ERR_free_strings();
	EVP_cleanup();
	return 0;
}
