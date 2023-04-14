#ifndef __PREFERENCES_H__
#define __PREFERENCES_H__

#include "config/config.h"

#include <QMainWindow>
#include <QAction>
#include <QMenu>
#include <QLabel>
#include <QSystemTrayIcon>
#include <QTreeWidgetItem>

#include <openssl/x509.h>

#include "widgets/waiting_spinner_widget.h"

#include "common/common.h"
#include "common/ticket.h"
#include "common/vpn_i_proxy.h"
#include "common/vpn_config_manager_i_proxy.h"
#include "common/tapdriver_manager_i_proxy.h"
#include "common/miscellaneous_service_i_proxy.h"

namespace Ui {
	class Preferences;
}

class AppInfo;
class AccessibleResourceDialog;
class ManageCertificate;
class VPNLogDialog;
class VPNItem;

class Preferences : public QMainWindow
{
	Q_OBJECT
public:
	Preferences(VPNConfigManagerProxy *configMgrProxy, TapDriverManagerProxy *tapDrvMgrProxy,
		MiscellaneousServiceProxy *miscSrvProxy);
	~Preferences();

	void showTrayMessage(const QString& title, const QString& message,
		QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::Information, int timeoutHint = 30000);

	// 启动所有设置了自动启动选项的VPN隧道
	void startTunnel();
	// 启动指定的VPN隧道
	void startTunnel(const QString& host, int port, const QString& protocol, const Ticket& ticket);

	void stopTunnel(const QString& host, int port, const QString& protocol, bool silent);

public slots:
	void checkForUpdate();
	void showAppInfo();
	void showPreferences();
	void showAccessibleResources();

protected:
	void changeEvent(QEvent *e);
	void closeEvent(QCloseEvent *e);

private slots:
#ifdef ENABLE_GUOMI
	void on_deviceCurrentList(const QString& providerName, const QStringList& deviceList, qint64 timestamp);
	void on_deviceListArrival(const QString& providerName, const QStringList& deviceList, qint64 timestamp);
	void on_deviceListRemove(const QString& providerName, const QStringList& deviceList, qint64 timestamp);
#endif
	void on_statisticsChanged(VPNItem *vpn_item);
	void on_toolBar_visibilityChanged(bool visible);
	void on_trvConnections_itemSelectionChanged();
	void on_trvConnections_customContextMenuRequested(const QPoint& pos);
	void on_trvConnections_itemDoubleClicked(QTreeWidgetItem *item, int column);
	void trayActivated(QSystemTrayIcon::ActivationReason reason);
	void refreshUi(VPNAgentI::State state, VPNItem *vpn_item);
	void connectVPN();
	void disconnectVPN();

	void newVPNConfig();
	void editVPNConfig();
	void deleteVPNConfig();

	void importVPNConfig();
	void exportVPNConfig();

	void manageCertificates();
	void editOptions();
	void viewLog();
	void viewVPNTunnelDetail();

	void exitApplication();
	void showToolbar();
	void showStatus();

	void changeLanguage(QAction *action);
	void changeUserPassword();
#ifdef ENABLE_GUOMI
	void changeDevicePIN();
#endif
	void clearCredentials();

#ifdef SELF_LOOP_REPLAY_TEST
	void selfLoopReplayTest();
#endif

private:
	friend class VPNObserverServant;

	void generateConnectParams(VPNItem *vpn_item, ServerEndpoint *remote, Ticket *ticket, QStringList *params,
		const Context& ctx);
#ifdef ENABLE_GUOMI
	void synchronizePin(const QString& providerName, const QString& appPath, const QString& pin);
	void processDeviceListRemove(VPNItem *vpn_item, const QString& providerName, const QStringList& deviceList);
#endif
	VPNItem* loadVPNConfig(qint32 id);
	VPNItem* loadVPNConfig(VPNConfig *config);
	bool isConnectionActive(int id) const;
	bool hasConnectionActive() const;
	bool hasConnectionEstablished() const;
	bool prepareConnectVPNImpl(VPNItem *vpn_item, const Context& ctx);
	Q_INVOKABLE void connectVPNImpl(VPNItem *vpn_item, const Context& ctx);
	Q_INVOKABLE void disconnectVPNImpl(VPNItem *vpn_item, bool silent);
	QString getSavedFingerprint();
	QString getCurrentFingerprint();
	void checkFingerprint();
	void initActions();
	void initTreeWidget();
	void createStatusBar();
	void createSystemTrayIcon();

	Ui::Preferences *m_ui;
	QMenu *trayIconMenu;
	QSystemTrayIcon *trayIcon;

	WaitingSpinnerWidget *spinner;

	QLabel *stateLabel;
	QLabel *statsRecvSpeedLabel;
	QLabel *statsSentSpeedLabel;

	bool needCheckFingerprint;
	QString savedFingerprint;
	QString currentFingerprint;

	AppInfo *appInfoDlg;
	VPNLogDialog *vpnLogDlg;
	AccessibleResourceDialog *accResDlg;

	VPNConfigManagerProxy *configMgrProxy;
	TapDriverManagerProxy *tapDrvMgrProxy;
	MiscellaneousServiceProxy *miscSrvProxy;

};

#endif
