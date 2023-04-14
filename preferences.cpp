#include <QApplication>
#include <QThread>
#include <QFileDialog>
#include <QProgressDialog>
#include <QProgressBar>
#include <QShowEvent>
#include <QToolTip>
#include <QDesktopWidget>
#include <QMovie>
#include <QDateTime>
#include <QTimer>
#include <QDir>
#include <QFile>
#include <QNetworkProxyFactory>
#include <QNetworkProxyQuery>
#include <QSysInfo>

#include "common/passphrase_generator.h"
#include "common/x509_certificate_util.h"
#include "common/message_box_util.h"
#include "common/dialog_util.h"
#include "common/translate.h"
#include "common/file_util.h"
#include "common/system_info.h"
#include "common/tapdriver_manager.h"
#include "common/locator.h"
#include "common/request_dispatcher.h"
#include "common/tapdriver_manager_i_proxy.h"
#include "common/encrypt_device_manager.h"
#include "common/vpn_i_proxy.h"
#include "common/progress_dialog.h"

#include "common/vpn_config.h"
#include "common/vpn_statistics.h"
#include "common/ticket.h"
#include "common/cipher.h"
#include "common/vpn_config_manager_i_proxy.h"

#include "policy/policy.h"
#include "policy/policy_engine_i_proxy.h"
#include "policy/policy_engine_servant.h"

#include "preferences.h"
#include "ui_preferences.h"

#include "change_password_dialog.h"
#include "change_pin_dialog.h"
#include "option_dialog.h"
#include "vpn_log_dialog.h"
#include "vpn_config_dialog.h"
#include "manage_certificate.h"
#include "vpn_tunnel_detail.h"
#include "vpn_item.h"
#include "vpn_observer_servant.h"
#include "vpn_input_agent_servant.h"
#include "appinfo.h"
#include "settings.h"
#include "single_application.h"
#include "accessible_resource_dialog.h"

Preferences::Preferences(VPNConfigManagerProxy *_configMgrProxy, TapDriverManagerProxy *_tapDrvMgrProxy,
		MiscellaneousServiceProxy *_miscSrvProxy)
	: QMainWindow(), m_ui(new Ui::Preferences), needCheckFingerprint(true), appInfoDlg(NULL), vpnLogDlg(NULL),
	accResDlg(NULL), configMgrProxy(_configMgrProxy), tapDrvMgrProxy(_tapDrvMgrProxy), miscSrvProxy(_miscSrvProxy)
{
	m_ui->setupUi(this);
	m_ui->trvConnections->setStyleSheet(QLatin1String("QTreeWidget::item{height:45px}"));
	this->setWindowTitle(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR));
	this->setWindowFlags(Qt::Window | Qt::MSWindowsFixedSizeDialogHint | Qt::NoDropShadowWindowHint);
	this->setFixedSize(this->width(), this->height());

	// 不要用this, 否则VPNLogDialog对话框总是在Preferences窗口上面
	this->vpnLogDlg = new VPNLogDialog(NULL);
	// 不要用this, 否则AccessibleResourceDialog对话框总是在Preferences窗口上面
	this->accResDlg = new AccessibleResourceDialog(NULL);

	this->createStatusBar();
	this->createSystemTrayIcon();
	this->initActions();
	this->initTreeWidget();

	// !!显示WaitingSpinnerWidget时, 阻塞用户输入
	spinner = new WaitingSpinnerWidget(Qt::WindowModal, this, true, false);
	spinner->setRoundness(60.0);
	spinner->setNumberOfLines(12);
	spinner->setLineLength(25);
	spinner->setLineWidth(10);
	spinner->setInnerRadius(25);
	spinner->setRevolutionsPerSecond(1);

#ifdef ENABLE_GUOMI
	QObject::connect(EncryptDeviceManager::instance(), SIGNAL(deviceCurrentList(const QString&, const QStringList&, qint64)),
		this, SLOT(on_deviceCurrentList(const QString&, const QStringList&, qint64)));
	QObject::connect(EncryptDeviceManager::instance(), SIGNAL(deviceListArrival(const QString&, const QStringList&, qint64)),
		this, SLOT(on_deviceListArrival(const QString&, const QStringList&, qint64)));
	QObject::connect(EncryptDeviceManager::instance(), SIGNAL(deviceListRemove(const QString&, const QStringList&, qint64)),
		this, SLOT(on_deviceListRemove(const QString&, const QStringList&, qint64)));
#endif

#ifdef ENABLE_UPDATER
	if (Settings::instance()->isCheckUpdate()) {
		QDateTime nextCheckUpdate = Settings::instance()->getLastCheckUpdate();
		nextCheckUpdate = nextCheckUpdate.addDays(1);	// 每天最多自动更新一次

		if (QDateTime::currentDateTime() > nextCheckUpdate) {
			// 随机化检查软件更新, 减小更新服务器负载
			const int interval = 5 + rand() % 3600;
			QTimer::singleShot(interval * 1000, this, SLOT(checkForUpdate()));	// 启动时检查软件更新
		}
	}
#endif

#if defined(SELF_LOOP_REPLAY_TEST) && defined(_DEBUG)
	const int interval = 60 + rand() % 60;
	QTimer::singleShot(interval * 1000, this, SLOT(selfLoopReplayTest()));
#endif
}

Preferences::~Preferences()
{
	if (vpnLogDlg) {
		vpnLogDlg->hide();
//		delete vpnLogDlg;
		vpnLogDlg->deleteLater();
	}
	if (accResDlg) {
		accResDlg->hide();
//		delete accResDlg;
		accResDlg->deleteLater();
	}

	delete m_ui;
}

void Preferences::initActions()
{
	QActionGroup *actionLanguageGroup = new QActionGroup(this);
	actionLanguageGroup->addAction(m_ui->actionEnglish);
	actionLanguageGroup->addAction(m_ui->actionChinese);
	QObject::connect(actionLanguageGroup, SIGNAL(triggered(QAction*)), this, SLOT(changeLanguage(QAction*)));

	m_ui->actionEnglish->setData(QLatin1Literal("en_US"));
	m_ui->actionChinese->setData(QLatin1Literal("zh_CN"));
	if (Settings::instance()->getLanguage().compare(QLatin1String("zh_CN"), Qt::CaseInsensitive) == 0)
		m_ui->actionChinese->setChecked(true);
	else
		m_ui->actionEnglish->setChecked(true);

	QObject::connect(m_ui->actionOptions, SIGNAL(triggered()), this, SLOT(editOptions()));

	m_ui->actionConnect->setEnabled(false);
	QObject::connect(m_ui->actionConnect, SIGNAL(triggered()), this, SLOT(connectVPN()));
	m_ui->actionDisconnect->setEnabled(false);
	QObject::connect(m_ui->actionDisconnect, SIGNAL(triggered()), this, SLOT(disconnectVPN()));

	QObject::connect(m_ui->actionNewVPN, SIGNAL(triggered()), this, SLOT(newVPNConfig()));
	m_ui->actionEditVPN->setEnabled(false);
	QObject::connect(m_ui->actionEditVPN, SIGNAL(triggered()), this, SLOT(editVPNConfig()));
	m_ui->actionDeleteVPN->setEnabled(false);
	QObject::connect(m_ui->actionDeleteVPN, SIGNAL(triggered()), this, SLOT(deleteVPNConfig()));

	QObject::connect(m_ui->actionImportVPN, SIGNAL(triggered()), this, SLOT(importVPNConfig()));
	m_ui->actionExportVPN->setEnabled(false);
	QObject::connect(m_ui->actionExportVPN, SIGNAL(triggered()), this, SLOT(exportVPNConfig()));

	QObject::connect(m_ui->actionCertificates, SIGNAL(triggered()), this, SLOT(manageCertificates()));

	m_ui->actionLog->setEnabled(false);
	QObject::connect(m_ui->actionLog, SIGNAL(triggered()), this, SLOT(viewLog()));

	m_ui->actionVPNTunnelDetail->setEnabled(false);
	QObject::connect(m_ui->actionVPNTunnelDetail, SIGNAL(triggered()), this, SLOT(viewVPNTunnelDetail()));

	m_ui->toolBar->setVisible(Settings::instance()->isShowToolbar());
	m_ui->actionToolbar->setChecked(Settings::instance()->isShowToolbar());
	QObject::connect(m_ui->actionToolbar, SIGNAL(triggered()), this, SLOT(showToolbar()));

	m_ui->statusbar->setVisible(Settings::instance()->isShowStatusBar());
	m_ui->actionStatus->setChecked(Settings::instance()->isShowStatusBar());
	QObject::connect(m_ui->actionStatus, SIGNAL(triggered()), this, SLOT(showStatus()));

	QObject::connect(m_ui->actionPreferences, SIGNAL(triggered()), this, SLOT(showPreferences()));

#ifdef ENABLE_INTEGRATION
	m_ui->actionResources->setEnabled(false);
	QObject::connect(m_ui->actionResources, SIGNAL(triggered()), this, SLOT(showAccessibleResources()));
	m_ui->actionChangePass->setEnabled(false);
	QObject::connect(m_ui->actionChangePass, SIGNAL(triggered()), this, SLOT(changeUserPassword()));
#else
	m_ui->menuView->removeAction(m_ui->actionResources);
	m_ui->toolBar->removeAction(m_ui->actionResources);
	m_ui->menuTool->removeAction(m_ui->actionChangePass);
	m_ui->toolBar->removeAction(m_ui->actionChangePass);
#endif

#ifdef ENABLE_GUOMI
	m_ui->actionChangePIN->setEnabled(false);
	QObject::connect(m_ui->actionChangePIN, SIGNAL(triggered()), this, SLOT(changeDevicePIN()));
#else
	m_ui->menuTool->removeAction(m_ui->actionChangePIN);
	m_ui->toolBar->removeAction(m_ui->actionChangePIN);
#endif

	m_ui->actionClearCredentials->setEnabled(false);
	QObject::connect(m_ui->actionClearCredentials, SIGNAL(triggered()), this, SLOT(clearCredentials()));

	QObject::connect(m_ui->actionAbout, SIGNAL(triggered()), this, SLOT(showAppInfo()));
#ifdef ENABLE_UPDATER
	m_ui->actionCheckForUpdates->setVisible(true);
	m_ui->actionCheckForUpdates->setEnabled(true);
	QObject::connect(m_ui->actionCheckForUpdates, SIGNAL(triggered()), this, SLOT(checkForUpdate()));
#else
	m_ui->actionCheckForUpdates->setVisible(false);
	m_ui->actionCheckForUpdates->setEnabled(false);
#endif

	QObject::connect(m_ui->actionExit, SIGNAL(triggered()), this, SLOT(exitApplication()));
}

void Preferences::initTreeWidget()
{
	m_ui->trvConnections->clear();
	m_ui->trvConnections->setSelectionMode(QAbstractItemView::SingleSelection);
	m_ui->trvConnections->setColumnCount(3);
	m_ui->trvConnections->setHeaderLabels(QStringList() << tr("ID") << tr("Name") << tr("State"));
	m_ui->trvConnections->header()->hideSection(0);
	// 宽度设置为160, 可以完整显示图标(crypted.png) + IP(218.242.126.165)
	m_ui->trvConnections->header()->resizeSection(1, 160);

	if (configMgrProxy) {
		QByteArray passphrase;	// 需要时才计算
		bool loadCreds = Settings::instance()->isSaveCredential();	// 是否需要加载认证信息
		if (loadCreds)
			passphrase = PassphraseGenerator::generateCredentialPassphrase();

		configMgrProxy->unload();	// 先卸载, 然后重新加载
		if (configMgrProxy->load(Settings::instance()->getAppSavePath(), passphrase, loadCreds)) {
			const QList<VPNConfig>& configList = configMgrProxy->list();

			for (int i = 0; i < configList.size(); ++i) {
				if (!loadVPNConfig(new VPNConfig(configList.at(i))))
					MessageBoxUtil::error(this, VPN_CLIENT_VER_PRODUCTNAME_STR, tr("The initialization configuration failed"));
			}
		}
	}
}

void Preferences::createStatusBar()
{
	stateLabel = new QLabel();
	stateLabel->setAlignment(Qt::AlignLeft|Qt::AlignVCenter);
	stateLabel->setIndent(6);

	statsRecvSpeedLabel = new QLabel();
	statsRecvSpeedLabel->setAlignment(Qt::AlignLeft|Qt::AlignVCenter);
	statsRecvSpeedLabel->setIndent(6);
	statsRecvSpeedLabel->setMinimumSize(120, 20);

	statsSentSpeedLabel = new QLabel();
	statsSentSpeedLabel->setAlignment(Qt::AlignLeft|Qt::AlignVCenter);
	statsSentSpeedLabel->setIndent(6);
	statsSentSpeedLabel->setMinimumSize(120, 20);

	statusBar()->setSizeGripEnabled(false);
	statusBar()->addWidget(stateLabel, 1);
	statusBar()->addWidget(statsRecvSpeedLabel, 0);
	statusBar()->addWidget(statsSentSpeedLabel, 0);
}

void Preferences::createSystemTrayIcon()
{
	trayIconMenu = new QMenu(this);
	trayIconMenu->setObjectName(QLatin1String("SYSTRAY_MENU"));

	trayIconMenu->addAction(m_ui->actionPreferences);
#ifdef ENABLE_INTEGRATION
	trayIconMenu->addAction(m_ui->actionResources);
#endif
	trayIconMenu->addSeparator();

	trayIconMenu->addAction(m_ui->actionAbout);
	trayIconMenu->addSeparator();

#if defined(ENABLE_GUOMI)
	trayIconMenu->addAction(m_ui->actionChangePIN);
	trayIconMenu->addSeparator();
#endif

	trayIconMenu->addAction(m_ui->actionExit);

	trayIcon = new QSystemTrayIcon(this);
	trayIcon->setIcon(QIcon(QLatin1String(":/images/vpn_client_tray.png")));
	trayIcon->setToolTip(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR));
	trayIcon->setContextMenu(trayIconMenu);
	trayIcon->show();

	QObject::connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)), this,
		SLOT(trayActivated(QSystemTrayIcon::ActivationReason)));
}

void Preferences::generateConnectParams(VPNItem *vpn_item, ServerEndpoint *remote, Ticket *ticket, QStringList *params,
		const Context& ctx)
{
#ifdef _WIN32
	*params << QLatin1String("--ctl-processid") << QString::number(QApplication::applicationPid());
#endif
	*params << QLatin1String("--ca") << Settings::instance()->getCAFileName();

	// OpenVPN 不能缓存密码, 因为客户可能随时修改密码
	*params << QLatin1String("--auth-nocache");

	const VPNConfig::AuthOptions authOptions = vpn_item->getVPNConfig()->getAuthOptions();

	// 禁用密码认证, 清理用户名和密码
	if (authOptions & VPNConfig::DisablePassword)
		vpn_item->removeCredentials(Credentials::UserName | Credentials::Password);

	// ?? 如果缓存了用户名密码自动启用密码认证
/*
	if (vpn_item->getVPNConfig()->getCredentials().hasCrediantials(Credentials::UserName
#ifdef STRONG_SECURITY_RESTRICTION
		| Credentials::Password
#endif
		)) {
		if (!(authOptions & VPNConfig::EnablePassword))
			vpn_item->getVPNConfig()->setAuthOptions(authOptions | VPNConfig::EnablePassword);
	}
*/

	// 票据认证、密码认证只能二选一
	if (!ticket) {
		if (vpn_item->getVPNConfig()->getAuthOptions() & VPNConfig::EnablePassword) {
			*params << QLatin1String("--auth-user-pass");
			*params << QLatin1String("--auth-retry") << QLatin1String("interact");
		}
	}

#ifdef ENABLE_GUOMI
	// !!只有插拔和用户点击事件才需要触发设备扫描; 不需要重复扫描加密设备, !!系统会自动追踪加密设备插拔事件
/*
	if (EncryptDeviceManager::instance()->getDeviceList().isEmpty())
		EncryptDeviceManager::instance()->enumDevice();
*/

	const QString libPath = QDir(QApplication::applicationDirPath()).absoluteFilePath(QLatin1String("lib"));
	*params << QLatin1String("--lib-path") << libPath;
	if (!EncryptDeviceManager::instance()->getDeviceList().isEmpty()) {
		*params << QLatin1String("--provider-name") << EncryptDeviceManager::instance()->getProviderName();
		*params << QLatin1String("--tls-cipher") << QLatin1String(ADP_SSL_WITH_HARDWARE_CIPHER_LIST);
	} else {
		*params << QLatin1String("--tls-cipher") << QLatin1String(ADP_SSL_NOWITH_HARDWARE_CIPHER_LIST);
	}

	// 添加要求硬件支持的加密算法不需要了, OpenVPN进程检测到加密设备时, 自行添加要求硬件支持的加密算法
#endif

	if (VPNConfig::System == vpn_item->getVPNConfig()->getProxyType()) {
		QList<QNetworkProxy> proxies;
		QNetworkProxyQuery npq;

		if (ServerEndpoint::Udp == remote->getProtocol()) {
			npq.setQueryType(QNetworkProxyQuery::UdpSocket);
			Q_FOREACH (QNetworkProxy p, QNetworkProxyFactory::systemProxyForQuery(npq)) {
				if (QNetworkProxy::Socks5Proxy == p.type() || QNetworkProxy::HttpProxy == p.type())
					proxies.append(p);
			}
		}

		// HTTP代理要求OpenVPN采用TCP协议
		if (proxies.isEmpty() && ServerEndpoint::Tcp == remote->getProtocol()) {
			npq.setQueryType(QNetworkProxyQuery::TcpSocket);
			Q_FOREACH (QNetworkProxy p, QNetworkProxyFactory::systemProxyForQuery(npq)) {
				if (QNetworkProxy::Socks5Proxy == p.type() || QNetworkProxy::HttpProxy == p.type())
					proxies.append(p);
			}
		}

		Q_FOREACH (QNetworkProxy p, proxies)
			qDebug() << "proxy::type=" << p.type() << ", host=" << p.hostName() << ", port=" << p.port();

		if (!proxies.isEmpty()) {
			QNetworkProxy proxy = proxies.at(0);	// 使用第一个合适的代理

			if (QNetworkProxy::Socks5Proxy == proxy.type())
				*params << QLatin1String("--socks-proxy") << proxy.hostName() << QString::number(proxy.port())
					<< QLatin1String("stdin");
			else if (QNetworkProxy::HttpProxy == proxy.type())
				*params << QLatin1String("--http-proxy") << proxy.hostName() << QString::number(proxy.port())
					<< QLatin1String("auto");
		}
	}

	// OpenVPN 客户端仅推送UV_开始的环境变量到服务端
	if (ticket)
		*params << QLatin1String("--setenv") << QLatin1String("UV_TICKET") << Ticket::encode(*ticket);

	// 推送客户端语言
	*params << QLatin1String("--setenv") << QLatin1String("UV_LANG") << Settings::instance()->getLanguage();

	// 推送客户端版本, 推送操作系统特征码, 不需要了, 由OpenVPN处理

	bool terminalBind = ctx.getAttribute(Context::TERMINAL_BIND).toBool();
	if (terminalBind)
		// 推送硬件特征码
		*params << QLatin1String("--setenv") << QLatin1String("UV_FINGERPRINT") << getCurrentFingerprint();

	// vpn.conf的内容通过配置文件传递给VPN进程, vpn_adv.conf的内容通过命令行参数传递给VPN进程
}

void Preferences::startTunnel()
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	for (int i = 0; i < root_item->childCount(); ++i) {
		if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
			if (vpn_item->getVPNConfig()->isAutoStart()) {
				VPNAgentI::State state = vpn_item->getState();
				Context localCtx(Context::getDefaultContext());

				localCtx.setAttribute(Context::TRUNC_VPN_LOG, QVariant::fromValue(true));
				if (state == VPNAgentI::ReadyToConnect || state == VPNAgentI::Disconnected) {
					if (prepareConnectVPNImpl(vpn_item, localCtx))
						connectVPNImpl(vpn_item, localCtx);
					break; // 不支持同时启动多个VPN隧道
				}
			}
		}
	}
}

void Preferences::startTunnel(const QString& host, int port, const QString& protocol, const Ticket& ticket)
{
	Q_UNUSED(ticket)

	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;
	ServerEndpoint endpoint(host, port, ServerEndpoint::string2Protocol(protocol));

	for (int i = 0; i < root_item->childCount(); ++i) {
		if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
			if (vpn_item->getVPNConfig()->getServerEndpoints().contains(endpoint)) {
				VPNAgentI::State state = vpn_item->getState();
				Context localCtx(Context::getDefaultContext());

				localCtx.setAttribute(Context::TRUNC_VPN_LOG, QVariant::fromValue(true));
				if (state == VPNAgentI::ReadyToConnect || state == VPNAgentI::Disconnected) {
					if (prepareConnectVPNImpl(vpn_item, localCtx))
						connectVPNImpl(vpn_item, localCtx);
				}
				break;
			}
		}
	}
}

void Preferences::stopTunnel(const QString& host, int port, const QString& protocol, bool silent)
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;
	ServerEndpoint endpoint(host, port, ServerEndpoint::string2Protocol(protocol));

	for (int i = 0; i < root_item->childCount(); ++i) {
		if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
			if (vpn_item->getVPNConfig()->getServerEndpoints().contains(endpoint)) {
				VPNAgentI::State state = vpn_item->getState();
				if (state == VPNAgentI::Connecting || state == VPNAgentI::Connected || state == VPNAgentI::Reconnecting)
					disconnectVPNImpl(vpn_item, silent);
				break;
			}
		}
	}
}

bool Preferences::isConnectionActive(int id) const
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	for (int i = 0; i < root_item->childCount(); ++i) {
		vpn_item = dynamic_cast<VPNItem*>(root_item->child(i));
		if (vpn_item && vpn_item->getVPNConfig()->getId() == id) {
			VPNAgentI::State state = vpn_item->getState();
			if (VPNAgentI::Connecting == state || VPNAgentI::Connected == state || VPNAgentI::Reconnecting == state
					|| VPNAgentI::Disconnecting == state)
				return true;
		}
	}

	return false;
}

bool Preferences::hasConnectionActive() const
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	for (int i = 0; i < root_item->childCount(); ++i) {
		vpn_item = dynamic_cast<VPNItem*>(root_item->child(i));
		if (vpn_item) {
			VPNAgentI::State state = vpn_item->getState();
			if (VPNAgentI::Connecting == state || VPNAgentI::Connected == state || VPNAgentI::Reconnecting == state
					|| VPNAgentI::Disconnecting == state)
				return true;
		}
	}

	return false;
}

bool Preferences::hasConnectionEstablished() const
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	for (int i = 0; i < root_item->childCount(); ++i) {
		vpn_item = dynamic_cast<VPNItem*>(root_item->child(i));
		if (vpn_item && VPNAgentI::Connected == vpn_item->getState())
			return true;
	}

	return false;
}

void Preferences::trayActivated(QSystemTrayIcon::ActivationReason reason)
{
	if (reason == QSystemTrayIcon::Trigger) {
		if (this->isVisible())
			this->hide();
		else {
			this->show();
			this->setFocus();
			this->activateWindow();
		}
	}
}

VPNItem* Preferences::loadVPNConfig(qint32 id)
{
	if (configMgrProxy) {
		const VPNConfig& config = configMgrProxy->get(id);

		if (!config.isEmpty())
			return loadVPNConfig(new VPNConfig(config));
	}

	return NULL;
}

VPNItem* Preferences::loadVPNConfig(VPNConfig *config)
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
#ifdef _WIN32
	if (!root_item || !config || !configMgrProxy || !tapDrvMgrProxy)
#else
	if (!root_item || !config || !configMgrProxy)
#endif
		return NULL;

	VPNItem *vpn_item = NULL;
	for (int i = 0; i < root_item->childCount(); ++i) {	// 检查配置是否已加载, 防止重复加载
		vpn_item = dynamic_cast<VPNItem*>(root_item->child(i));
		if (vpn_item != NULL && vpn_item->getVPNConfig()->getId() == config->getId()) {
			*vpn_item->getVPNConfig() = *config;	// 更新配置
			return vpn_item;
		}
	}

	// 获取当前用户名
	const QString currentUser = SystemInfo::getCurrentUser();
	Q_ASSERT(!currentUser.isEmpty());

	// 用户可能启动多个不同的前台程序(GUI, BROWSER ...)，用currentUser而不是sessionIdentify标识后台服务

	// 定位VPNAgentI
	const QString agentIdentify = QString("VPNAgentI:%1:%2").arg(currentUser).arg(config->getId());
	VPNAgentProxy *agentProxy = Locator::locate<VPNAgentProxy>(VPN_LOCAL_HOST, VPN_SERVICE_PORT, agentIdentify);
	if (!agentProxy)
		return NULL;

	// 初始化VPNAgentI
	agentProxy->initialize(config->getPath(), config->getPath());

	// 定位后端PolicyEngineI
	const QString backPolicyEngineIdentify = QString("VPNAgentI:%1:%2:BackPolicyEngineI").arg(currentUser).arg(config->getId());
	PolicyEngineProxy *backPolicyEngineProxy =
		Locator::locate<PolicyEngineProxy>(VPN_LOCAL_HOST, VPN_SERVICE_PORT, backPolicyEngineIdentify);
	if (!backPolicyEngineProxy)
		return NULL;

	const QHostAddress &localHost = agentProxy->getConnection()->localAddress();
	quint16 localPort = agentProxy->getConnection()->localPort();

	// 注册输入代理
	const QString inputAgentIdentify = QString("VPNInputAgentI:%1:%2").arg(currentUser).arg(config->getId());
	VPNInputAgentI *inputAgentI = new VPNInputAgentServant(this, config, inputAgentIdentify, getCurrentFingerprint());
	RequestDispatcher::registerServant(QLatin1String("VPNInputAgentI"), dynamic_cast<VPNInputAgentServant*>(inputAgentI));
//	agentProxy->unregisterInputAgent();
	agentProxy->registerInputAgent(localHost, localPort, inputAgentIdentify);

	// 注册前端PolicyEngineI
	const QString frontPolicyEngineIdentify = QString("VPNAgentI:%1:%2:FrontPolicyEngineI").arg(currentUser).arg(config->getId());
	PolicyEngineServant *frontPolicyEngineServant = new PolicyEngineServant(frontPolicyEngineIdentify, true,
		agentProxy, backPolicyEngineProxy);
	RequestDispatcher::registerServant(QLatin1String("PolicyEngineI"), frontPolicyEngineServant);
//	agentProxy->unregisterPolicyEngine();
	agentProxy->registerPolicyEngine(localHost, localPort, frontPolicyEngineIdentify);

	// 生成当前VPN运行上下文
	VPNContext *vpnContext = new VPNContext(agentProxy, inputAgentI, frontPolicyEngineServant, backPolicyEngineProxy);
	vpn_item = new VPNItem(root_item, vpnContext, config);

	// 注册观察者
	const QString observerIdentify = QString("VPNObserverI:%1:%2").arg(currentUser).arg(config->getId());
	VPNObserverServant *observerServant = new VPNObserverServant(this, observerIdentify, vpn_item,
		configMgrProxy, tapDrvMgrProxy);
	RequestDispatcher::registerServant(QLatin1String("VPNObserverI"), observerServant);
	vpnContext->setVPNObserverI(observerServant);
	agentProxy->unregisterObserver(localHost, localPort, observerIdentify);
	agentProxy->registerObserver(localHost, localPort, observerIdentify);

	// 同步UI到当前状态, 不需要了; 由服务端发起同步
//	observerServant->notify(vpn_item->getState(), vpn_item->getVPNTunnel(), Context::getDefaultContext());

	// 注册信号
	QObject::connect(observerServant, SIGNAL(stateChanged(VPNAgentI::State, VPNItem*)), this,
		SLOT(refreshUi(VPNAgentI::State, VPNItem*)));
	QObject::connect(observerServant, SIGNAL(statisticsChanged(VPNItem*)), this,
		SLOT(on_statisticsChanged(VPNItem*)));

	QObject::connect(observerServant, SIGNAL(stateChanged(VPNAgentI::State, VPNItem*)), this->accResDlg,
		SLOT(on_stateChanged(VPNAgentI::State, VPNItem*)));
	QObject::connect(observerServant, SIGNAL(accessibleResourcesChanged(VPNItem*)), this->accResDlg,
		SLOT(on_accessibleResourcesChanged(VPNItem*)));

	m_ui->trvConnections->addTopLevelItem(vpn_item);
	return vpn_item;
}

void Preferences::changeEvent(QEvent *e)
{
	switch (e->type()) {
	case QEvent::LanguageChange: {
		QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
		VPNItem *vpn_item = NULL;

		m_ui->retranslateUi(this);
		m_ui->trvConnections->setHeaderLabels(QStringList() << tr("ID") << tr("Name") << tr("State"));

		for (int i = 0; i < root_item->childCount(); ++i) {
			if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
				VPNContext *vpnContext = vpn_item->getVPNContext();
				VPNAgentI::State state = vpn_item->getState();
				Context localCtx(Context::getDefaultContext());

				localCtx.setAttribute(QLatin1String("LOCAL_UI_EVENT"), QVariant::fromValue(true));
				vpnContext->getVPNObserverI()->notify(state, vpn_item->getVPNTunnel(), localCtx);
			}
		}
		break;
	}
	default:
		break;
	}

	QMainWindow::changeEvent(e);
}

void Preferences::closeEvent(QCloseEvent *e)
{
	if (trayIcon && trayIcon->isVisible()) {
		hide();
		e->ignore();
	}
}

void Preferences::exitApplication()
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	// 检查是否有活动连接
	if (hasConnectionActive()) {
		if (!MessageBoxUtil::confirm(this, tr("A connection is still connected"), tr("Do you want to disconnect the connection?")))
			return;	// 放弃关闭
	}

	QApplication::setOverrideCursor(Qt::WaitCursor);

	for (int i = 0; i < root_item->childCount(); ++i) {
		if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
			VPNContext *vpnContext = vpn_item->getVPNContext();
			VPNAgentI::State state = vpn_item->getState();
			if (state == VPNAgentI::Connecting || state == VPNAgentI::Connected || state == VPNAgentI::Reconnecting) {
				vpn_item->getVPNConfig()->setAutoReconnect(false);	// 关闭自动重连
				vpnContext->getVPNAgentI()->disconnect();
			}
		}
	}

	this->trayIcon->hide();

	if (configMgrProxy)
		configMgrProxy->unload();	// 卸载所有配置, 删除所有临时配置

	QApplication::processEvents();

	Locator::unregisterAllConnections();

	QApplication::restoreOverrideCursor();

	QApplication::exit(0);
}

void Preferences::showTrayMessage(const QString& title, const QString& message, QSystemTrayIcon::MessageIcon icon, int timeoutHint)
{
	if (Settings::instance()->isShowBallonMessage())
		this->trayIcon->showMessage(title, message, icon, timeoutHint);
}

void Preferences::showAppInfo()
{
	// 没有活动模态对话框才可以显示About对话框
	QWidget *widget = QApplication::activeModalWidget();
	if (!widget) {
		AppInfo appInfo(this, AppInfo::tr("About"));
		appInfo.exec();
	}
}

void Preferences::showToolbar()
{
	m_ui->toolBar->setVisible(m_ui->actionToolbar->isChecked());
	Settings::instance()->setShowToolbar(m_ui->actionToolbar->isChecked());
}

void Preferences::showStatus()
{
	m_ui->statusbar->setVisible(m_ui->actionStatus->isChecked());
	Settings::instance()->setShowStatusBar(m_ui->actionStatus->isChecked());
}

bool Preferences::prepareConnectVPNImpl(VPNItem *vpn_item, const Context& ctx)
{
	VPNContext *vpnContext = vpn_item->getVPNContext();
	VPNObserverI *observerI = vpnContext->getVPNObserverI();

	// 必须处于未连接状态
#ifdef _DEBUG
	VPNAgentI::State state = vpn_item->getState();
	Q_ASSERT(state == VPNAgentI::ReadyToConnect || state == VPNAgentI::Disconnected);
#endif

	// 更新到正在连接状态
	observerI->notify(VPNAgentI::Connecting, vpn_item->getVPNTunnel(), ctx);
	QApplication::processEvents();

#ifdef ENABLE_GUOMI
	// !!只有插拔和用户点击事件才需要触发设备扫描; 不需要强制扫描加密设备, !!系统会自动追踪加密设备插拔事件
/*
	if (EncryptDeviceManager::instance()->getDeviceList().isEmpty()) {
		observerI->notify(QApplication::translate("VPNAgentI", "Probe encrypt device ..."), ctx);
		EncryptDeviceManager::instance()->enumDevice();
	}
*/
#endif

	vpn_item->getVPNConfig()->setAutoReconnect(false);

	// 初始化ServerEndpoint选择器
	vpnContext->getServerEndpointSelector()->initialize(vpn_item->getVPNEdge().getClusterAlgorithm(),
		vpn_item->getVPNConfig()->getServerEndpoints(), vpn_item->getVPNEdge().getClusterEndpoints());

	// 初始化是否重新选择证书
	bool reselectCertificate = false;
	if (vpn_item->getVPNConfig()->getCredentials().hasCrediantials(Credentials::CertificateInfo)) {
		const QString &source = vpn_item->getVPNConfig()->getCredentials().getCertificateInfo().getSource();
		X509 *x509 = vpn_item->getVPNConfig()->getCredentials().getCertificateInfo().getCertificate();

		if (source.compare(PKCS12_FILE_SOURCE, Qt::CaseInsensitive) == 0) {
			const QString pkcs12Path = Settings::instance()->getAppSavePath();
			const QByteArray secretKey = PassphraseGenerator::generatePKCS12Passphrase();
			const QMap<X509*, QString> x509Map = X509CertificateUtil::load_from_pkcs12_path(pkcs12Path, secretKey);
			if (X509CertificateUtil::contains(x509Map, x509))
				reselectCertificate = true;
			else
				// 清理所有缓存的安全信息, 证书被废弃, 不大可能重新导入这张证书了
				vpn_item->getVPNConfig()->getCredentials().clear();
			X509CertificateUtil::free_all_cert(x509Map);

#ifdef _WIN32
		} else if (source.compare(MS_CRYPTAPI_SOURCE, Qt::CaseInsensitive) == 0) {
			const QMap<X509*, QString> x509Map = X509CertificateUtil::load_from_mscapi(QLatin1String("MY"));
			if (X509CertificateUtil::contains(x509Map, x509))
				reselectCertificate = true;
			else
				// 清理所有缓存的安全信息, 证书被废弃, 不大可能重新导入这张证书了
				vpn_item->getVPNConfig()->getCredentials().clear();
			X509CertificateUtil::free_all_cert(x509Map);
#endif
		}
	}
	vpn_item->setReselectCertificate(reselectCertificate);

	// 初始化是否重新输入代理用户名密码
	if (vpn_item->getVPNConfig()->getCredentials().hasCrediantials(Credentials::ProxyUserName))
		vpn_item->setReinputProxyPassword(true);
	else
		vpn_item->setReinputProxyPassword(false);

	// 初始化是否重新输入用户名密码
	if (vpn_item->getVPNConfig()->getCredentials().hasCrediantials(Credentials::UserName))
		vpn_item->setReinputPassword(true);
	else
		vpn_item->setReinputPassword(false);

	// 初始化密码输入次数
	vpn_item->getAndSetProxyAuthPasswordNum(0);
	vpn_item->getAndSetAuthPasswordNum(0);

#ifdef ENABLE_CLONE
	// 检查机器指纹, 用来解决系统克隆问题
	if (this->needCheckFingerprint)
		checkFingerprint();
#endif

	// 选择初始ServerEndpoint
	observerI->notify(QApplication::translate("VPNAgentI", "Select optimal gateway ..."), ctx);
	bool ok = vpnContext->getServerEndpointSelector()->select();

	if (ok) {
		// 准备成功, 并且有多个ServerEndpoint时; 设置自动重连标志, 失败时尝试其它服务器
		if (vpn_item->getVPNConfig()->getServerEndpoints().size() > 1)
			vpn_item->getVPNConfig()->setAutoReconnect(ok);
	} else {
		// 准备连接失败, 更新到准备连接状态
		observerI->notify(VPNAgentI::ReadyToConnect, vpn_item->getVPNTunnel(), ctx);
		QApplication::processEvents();
	}

	return ok;
}

void Preferences::connectVPNImpl(VPNItem *vpn_item, const Context& ctx)
{
	// 重连时, 检查连接是否由这个Session发起; 如果不是, 立即退出
	if (!sessionIdentifyEqual(Context::getDefaultContext(), ctx)) {
		return;
	}

	VPNContext *vpnContext = vpn_item->getVPNContext();
	VPNAgentProxy *agentProxy = vpnContext->getVPNAgentI();
	VPNObserverI *observerI = vpnContext->getVPNObserverI();

	Context localCtx(ctx);

	// 设置连接唯一标识, 使用本机当前时间作为唯一标识, 可解决多个客户端连接唯一标识同步问题
	const qint64 connectSequence = QDateTime::currentMSecsSinceEpoch();
	vpn_item->setConnectSequence(connectSequence);
	localCtx.setAttribute(Context::VPN_CONNECT_SEQUENCE, QVariant::fromValue(connectSequence));
	// 初始化策略引擎计数器
	localCtx.setAttribute(Context::POLICY_ENGINE_COUNTER, QVariant::fromValue(0));

	// 生成连接参数
	observerI->notify(QApplication::translate("VPNAgentI", "Generate negotiate parameters ..."), localCtx);
	QApplication::processEvents();

	ServerEndpoint remote = vpnContext->getServerEndpointSelector()->getServerEndpoint();
	Q_ASSERT(!remote.isEmpty());
	QStringList params;

	generateConnectParams(vpn_item, &remote, NULL, &params, localCtx);
	agentProxy->connect(remote, params, localCtx);
}

void Preferences::disconnectVPNImpl(VPNItem *vpn_item, bool silent)
{
	Q_UNUSED(silent)

	VPNContext *vpnContext = vpn_item->getVPNContext();
	VPNAgentProxy *agentProxy = vpnContext->getVPNAgentI();
	VPNObserverI *observerI = vpnContext->getVPNObserverI();

#if defined(SELF_LOOP_REPLAY_TEST) && defined(_DEBUG)
	if (vpn_item->getState() == VPNAgentI::Connected && !silent) {
		if (!MessageBoxUtil::confirm(this, tr("Disconnect"), tr("Do you want to disconnect the connection?")))
			return;
	}

	// 用户主动断开, 清理缓存的安全信息
	if (!Settings::instance()->isSaveCredential()) {
		vpn_item->clearCredentials();
	}
#endif

	// 更新到正在断开连接状态
	observerI->notify(VPNAgentI::Disconnecting, vpn_item->getVPNTunnel(), Context::getDefaultContext());
	QApplication::processEvents();

	vpn_item->getVPNConfig()->setAutoReconnect(false);	// 关闭自动重连
	agentProxy->disconnect();
}

void Preferences::connectVPN()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (!configMgrProxy || selecteds_items.size() != 1)
		return;

	VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));
	VPNAgentI::State state = vpn_item->getState();
	Context localCtx(Context::getDefaultContext());

	localCtx.setAttribute(Context::TRUNC_VPN_LOG, QVariant::fromValue(true));
	if (state == VPNAgentI::ReadyToConnect || state == VPNAgentI::Disconnected) {
		if (prepareConnectVPNImpl(vpn_item, localCtx))
			connectVPNImpl(vpn_item, localCtx);
	}
}

void Preferences::disconnectVPN()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (!configMgrProxy || selecteds_items.size() != 1)
		return;

	VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));
	VPNAgentI::State state = vpn_item->getState();

	if (VPNAgentI::Connecting == state || VPNAgentI::Connected == state || VPNAgentI::Reconnecting == state) {
		if (MessageBoxUtil::confirm(this, tr("A connection is still connected"), tr("Do you want to disconnect the connection?")))
			disconnectVPNImpl(vpn_item, false);
	}
}

QString Preferences::getSavedFingerprint()
{
	if (savedFingerprint.isEmpty()) {
		const QString fingerprintFileName =
			QDir(FileUtil::getAppSavePath(QLatin1String(VPN_CONFIG_DIR_NAME))).absoluteFilePath(FINGERPRINT_FILE);
		savedFingerprint = miscSrvProxy->getFingerprint(fingerprintFileName, Context::getDefaultContext());
	}
	return savedFingerprint;
}

QString Preferences::getCurrentFingerprint()
{
	if (currentFingerprint.isEmpty()) {
		currentFingerprint = miscSrvProxy->generateFingerprint(Context::getDefaultContext());
		Q_ASSERT(!currentFingerprint.isEmpty());
	}
	return currentFingerprint;
}

void Preferences::checkFingerprint()
{
#ifdef _WIN32
	bool saveFingerprint = false;	// Tap Driver删除成功后, 才能保存指纹

	if (getSavedFingerprint() != getCurrentFingerprint()) {
		// XP无法通过后台服务安装TAP驱动; 假定当前用户是管理员, 尝试在前端安装
		if (QSysInfo::kernelVersion().startsWith("5") /* < 6*/) {
			TapDriverManager tapDrvMgr;
			tapDrvMgr.initialize(QString(QLatin1String("%1/driver")).arg(QApplication::applicationDirPath()));
			if (tapDrvMgr.removeTapDriver()) {
				saveFingerprint = true;	// Tap Driver删除成功, 保存指纹
				tapDrvMgr.installTapDriver();
			}
		} else {
			if (tapDrvMgrProxy->removeTapDriver()) {
				saveFingerprint = true;	// Tap Driver删除成功, 保存指纹
				tapDrvMgrProxy->installTapDriver();
			}
		}
	} else
		this->needCheckFingerprint = false;	// 指纹未变化, 不需要再检查了

	if (saveFingerprint) {
		this->needCheckFingerprint = false;	// 指纹已更新, 不需要再检查了
		this->savedFingerprint = this->currentFingerprint;
		const QString fingerprintFileName =
			QDir(FileUtil::getAppSavePath(QLatin1String(VPN_CONFIG_DIR_NAME))).absoluteFilePath(FINGERPRINT_FILE);
		miscSrvProxy->saveFingerprint(fingerprintFileName, this->currentFingerprint, Context::getDefaultContext());
	}
#endif
}

void Preferences::checkForUpdate()
{
#ifdef ENABLE_UPDATER
	ActionGuard actionGuard(m_ui->actionCheckForUpdates, false);

	// 更新检查更新时间
	Settings::instance()->setLastCheckUpdate(QDateTime::currentDateTime());

	// FIXME
	QString reason = tr("FIXME, unimplemented!");
	MessageBoxUtil::error(this, tr("Update"), tr("Update fail") + ", " + reason);
#endif
}

#ifdef ENABLE_GUOMI
void Preferences::synchronizePin(const QString& providerName, const QString& appPath, const QString& pin)
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	for (int i = 0; i < root_item->childCount(); ++i) {
		if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
			Credentials &cred = vpn_item->getVPNConfig()->getCredentials();
			if (cred.getCertificateInfo().getSource() == QLatin1String(ENCRYPT_DEVICE_SOURCE) &&
					cred.getCertificateInfo().getIdentity() == appPath) {
				cred.setKeyPassword(pin.toLocal8Bit());	// 私钥保护密码不保存, 每次插拔必须重新输入
			}
		}
	}
}

void Preferences::on_deviceCurrentList(const QString& providerName, const QStringList& deviceList, qint64 timestamp)
{
	bool actionChangePIN_enabled = false;

	// 记住扫描到的设备提供者
	if (!providerName.isEmpty())
		Settings::instance()->setLastProviderName(EncryptDeviceManager::instance()->getProviderName());

	if (!deviceList.isEmpty())
		actionChangePIN_enabled = EncryptDeviceManager::instance()->supportsChangeDevicePIN(providerName);

	m_ui->actionChangePIN->setEnabled(actionChangePIN_enabled);
}

void Preferences::on_deviceListArrival(const QString& providerName, const QStringList& deviceList, qint64 timestamp)
{
	this->showTrayMessage(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR),
		tr("Device") + QLatin1String(" ") + deviceList.join(QLatin1String(", ")) + QLatin1String(" ") + tr("arrival"));
}

void Preferences::processDeviceListRemove(VPNItem *vpn_item, const QString& providerName, const QStringList& deviceList)
{
	VPNContext *vpnContext = vpn_item->getVPNContext();
	PolicyEngineI *policyEngineI = vpnContext->getBackPolicyEngineI();
	VPNAgentI::State state = vpn_item->getState();
	const PolicyEngineI::ApplyPoint point = PolicyEngineI::DeviceRemoved;

	// 不能清理缓存的安全信息, 下次连接, 用户会重新插入加密设备

	// Context::REMOVED_ENCRYPT_DEVICES比较大, 复制一个本地上下文, 不要放全局上下文
	Context localCtx(Context::getDefaultContext());

	localCtx.setAttribute(Context::REMOVED_ENCRYPT_DEVICES, deviceList);

	if ((state == VPNAgentI::Connecting || state == VPNAgentI::Connected || state == VPNAgentI::Reconnecting)
			&& policyEngineI) {
		if (policyEngineI->hasPolicy(point, localCtx)) {
			bool autoReconnect = vpn_item->getVPNConfig()->isAutoReconnect();
			vpn_item->getVPNConfig()->setAutoReconnect(false);	// 关闭自动重连, 通知服务端

			localCtx.setAttribute(Context::VPN_CONFIG, QVariant::fromValue(*vpn_item->getVPNConfig()));
			localCtx.setAttribute(Context::VPN_TUNNEL, QVariant::fromValue(vpn_item->getVPNTunnel()));
			ApplyResult result = policyEngineI->applyPolicy(point, localCtx);
			if (result.getResult() == ApplyResult::Success)
				vpn_item->getVPNConfig()->setAutoReconnect(autoReconnect);	// 无影响
			else {
				bool result = QMetaObject::invokeMethod(this, "disconnectVPNImpl", Qt::QueuedConnection,
					Q_ARG(VPNItem*, vpn_item), Q_ARG(bool, true));
				Q_ASSERT_X(result, "disconnectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
//				disconnectVPNImpl(vpn_item, true);	// 断开隧道
			}
		}
	}
}

void Preferences::on_deviceListRemove(const QString& providerName, const QStringList& deviceList, qint64 timestamp)
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	this->showTrayMessage(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR),
		tr("Device") + QLatin1String(" ") + deviceList.join(QLatin1String(", ")) + QLatin1String(" ") + tr("remove"));

	for (int i = 0; i < root_item->childCount(); ++i) {
		if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
			// !!如果timestamp在连接发起前, 忽略加密设备移除事件
			if (timestamp > vpn_item->getConnectSequence()) {
				// 私钥保护密码, 每次插拔必须重新输入
				vpn_item->getVPNConfig()->getCredentials().removeCredentials(Credentials::KeyPassword);
				processDeviceListRemove(vpn_item, providerName, deviceList);
			}
		}
	}
}
#endif

void Preferences::on_toolBar_visibilityChanged(bool visible)
{
	if (m_ui->actionToolbar->isChecked() != visible) {
		m_ui->actionToolbar->setChecked(visible);
		m_ui->actionToolbar->triggered(visible);
	}
}

void Preferences::on_statisticsChanged(VPNItem *vpn_item)
{
	// 不支持同时启动多个VPN隧道
	Q_ASSERT(vpn_item);
	QString recvSpeedText, sentSpeedText;
	bool kbps = true;

	float recvSpeed = vpn_item->getVPNStatistics().getRecvSpeed();
	float sentSpeed = vpn_item->getVPNStatistics().getSentSpeed();

	if (recvSpeed > 1024.0f || sentSpeed > 1024.0f) {
		recvSpeed = recvSpeed / 1024.0f;
		sentSpeed = sentSpeed / 1024.0f;
		kbps = false;
	}

	recvSpeedText.append(tr("receive")).append(QLatin1Char(' '));
	recvSpeedText.append(QString::number(recvSpeed, 'f', 2)).append(kbps ? tr("KB/s") : tr("MB/s"));

	sentSpeedText.append(tr("sent")).append(QLatin1Char(' '));
	sentSpeedText.append(QString::number(sentSpeed,  'f', 2)).append(kbps ? tr("KB/s") : tr("MB/s"));

	statsRecvSpeedLabel->setText(recvSpeedText);
	statsSentSpeedLabel->setText(sentSpeedText);
}

void Preferences::on_trvConnections_itemSelectionChanged()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (selecteds_items.size() == 0) {
		m_ui->actionConnect->setEnabled(false);
		m_ui->actionDisconnect->setEnabled(false);
		m_ui->actionEditVPN->setEnabled(false);
		m_ui->actionDeleteVPN->setEnabled(false);
		m_ui->actionExportVPN->setEnabled(false);
		m_ui->actionLog->setEnabled(false);
		m_ui->actionVPNTunnelDetail->setEnabled(false);
#ifdef ENABLE_INTEGRATION
		m_ui->actionResources->setEnabled(false);
		m_ui->actionChangePass->setEnabled(false);
#endif
#ifdef ENABLE_GUOMI
		m_ui->actionChangePIN->setEnabled(false);
#endif
		m_ui->actionClearCredentials->setEnabled(false);

		statsRecvSpeedLabel->setText(QLatin1String(""));
		statsSentSpeedLabel->setText(QLatin1String(""));
		stateLabel->setText(QLatin1String(""));

	} else if (selecteds_items.size() == 1) {
		VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));
		Q_ASSERT(vpn_item);
		refreshUi(vpn_item->getState(), vpn_item);
	}
}

void Preferences::refreshUi(VPNAgentI::State state, VPNItem *vpn_item)
{
#ifdef ENABLE_INTEGRATION
	// !!连接已建立成功后可以显示可见资源对话框(未选择VPNItem也可以)
	m_ui->actionResources->setEnabled(hasConnectionEstablished());
#endif

	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (selecteds_items.size() != 1)
		return;

	// 选择了VPNItem才可以查看日志和导出配置(不依赖VPNAgentI当前状态)
	m_ui->actionLog->setEnabled(true);
	m_ui->actionExportVPN->setEnabled(true);

	VPNItem *selected_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));
	VPNContext *vpnContext = vpn_item->getVPNContext();
	VPNConfig *config = vpn_item->getVPNConfig();

	if (Settings::instance()->isSaveCredential() && vpn_item->getVPNConfig()->getCredentials().hasAnyCrediantials())
		vpn_item->setIcon(1, QIcon(QLatin1String(":/images/crypted.png")));
	else
		vpn_item->setIcon(1, QIcon());

	if (state == VPNAgentI::ReadyToConnect || state == VPNAgentI::Disconnected) {
		// 不支持同时启动多个VPN隧道
		m_ui->actionClearCredentials->setEnabled(config->getCredentials().hasAnyCrediantials());
		m_ui->actionChangePass->setEnabled(false);
		m_ui->actionEditVPN->setEnabled(!config->isTemporary());
		m_ui->actionDeleteVPN->setEnabled(true);
		m_ui->actionConnect->setEnabled(!hasConnectionActive());
		m_ui->actionDisconnect->setEnabled(false);
		m_ui->actionVPNTunnelDetail->setEnabled(false);
		if (QObject::sender() == dynamic_cast<QObject*>(vpnContext->getVPNObserverI())) {
			statsRecvSpeedLabel->setText(""); statsSentSpeedLabel->setText("");
		}

	} else {
		// 连接活动时, Action应该同步到当前被选择的VPNItem
		if (selected_item == vpn_item) {
			m_ui->actionClearCredentials->setEnabled(false);
			m_ui->actionEditVPN->setEnabled(false);
			m_ui->actionDeleteVPN->setEnabled(false);
			m_ui->actionConnect->setEnabled(false);

			if (VPNAgentI::Connecting == state || VPNAgentI::Connected == state || VPNAgentI::Reconnecting == state) {
				m_ui->actionChangePass->setEnabled(state == VPNAgentI::Connected &&
					(config->getAuthOptions() & VPNConfig::EnablePassword) &&
					!vpn_item->getVPNEdge().getPasswordService().isEmpty());
				m_ui->actionDisconnect->setEnabled(true);
				m_ui->actionVPNTunnelDetail->setEnabled(state == VPNAgentI::Connected);

			} else if (state == VPNAgentI::Disconnecting) {
				m_ui->actionDisconnect->setEnabled(false);
				m_ui->actionVPNTunnelDetail->setEnabled(false);

			} else {
				MessageBoxUtil::error(this,
					VPN_CLIENT_VER_PRODUCTNAME_STR, tr("VPN state error") + ", " + Translate::translateVPNState(state));
			}
		}
	}

	stateLabel->setText(Translate::translateVPNState(state));
}

void Preferences::on_trvConnections_itemDoubleClicked(QTreeWidgetItem* item, int column)
{
	Q_UNUSED (column)

	VPNItem *vpn_item = dynamic_cast<VPNItem*>(item);
	if (vpn_item) {
		VPNAgentI::State state = vpn_item->getState();
		Context localCtx(Context::getDefaultContext());

		localCtx.setAttribute(Context::TRUNC_VPN_LOG, QVariant::fromValue(true));
		if (state == VPNAgentI::ReadyToConnect || state == VPNAgentI::Disconnected) {
			if (hasConnectionActive())
				MessageBoxUtil::tooltip(this, tr("Have active connection, disconnected please."), 2000);
			else if (prepareConnectVPNImpl(vpn_item, localCtx))
				connectVPNImpl(vpn_item, localCtx);
		} else if (VPNAgentI::Connecting == state || VPNAgentI::Connected == state || VPNAgentI::Reconnecting == state) {
			if (MessageBoxUtil::confirm(this, tr("A connection is still connected"), tr("Do you want to disconnect the connection?")))
				disconnectVPNImpl(vpn_item, false);
		} else {
			;	// 处于其它状态(例如: VPNAgentI::Disconnecting), 忽略
		}
	}
}

void Preferences::newVPNConfig()
{
	if (!configMgrProxy)
		return;

	VPNConfigDialog dialog(this, VPNConfigDialog::tr("VPN config"), NULL, configMgrProxy);
	if (dialog.exec() == QDialog::Accepted) {
		VPNConfig *config = dialog.getVPNConfig();
		QByteArray passphrase;	// 需要时才计算
		spinner->start(); // start spinning
		const qint32 id = configMgrProxy->save(*config, passphrase, VPNConfigManagerI::O_Config);
		spinner->stop();

		if (id >= 0) { // id >= 0 表示保存成功
			loadVPNConfig(id);
		} else {
			MessageBoxUtil::error(this, VPN_CLIENT_VER_PRODUCTNAME_STR, tr("Save VPN config fail"));
		}
		delete config;
	}
}

void Preferences::editVPNConfig()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (!configMgrProxy || selecteds_items.size() != 1)
		return;

	VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));
	VPNConfigDialog dialog(this, VPNConfigDialog::tr("VPN config"), vpn_item->getVPNConfig(), configMgrProxy);

	if (dialog.exec() == QDialog::Accepted) {
		VPNConfig *config = dialog.getVPNConfig();
		QByteArray passphrase;	// 需要时才计算
		spinner->start(); // start spinning
		const qint32 id = configMgrProxy->save(*config, passphrase, VPNConfigManagerI::O_Config);
		spinner->stop();

		if (id >= 0) {	// id >= 0 表示保存成功
			*config = configMgrProxy->get(id);	// 重新加载
			vpn_item->setText(1, config->getName());
		} else
			MessageBoxUtil::error(this, VPN_CLIENT_VER_PRODUCTNAME_STR, tr("Modify VPN config fail"));
	}
}

void Preferences::deleteVPNConfig()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (!configMgrProxy || selecteds_items.size() != 1)
		return;

	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));

	if (MessageBoxUtil::confirm(this, VPNConfigDialog::tr("VPN config"), tr("Do you want to remove vpn config?"))) {
		spinner->start(); // start spinning
		configMgrProxy->remove(vpn_item->getVPNConfig()->getId());
		spinner->stop();

		int index = m_ui->trvConnections->indexOfTopLevelItem(vpn_item);
		if (root_item->takeChild(index))
			delete vpn_item;
	}
}

void Preferences::importVPNConfig()
{
	if (!configMgrProxy)
		return;

	const QString vpnconfigFile = QFileDialog::getOpenFileName(this, tr("Select VPN config file"),
		Settings::instance()->getLastAccessPath(), tr("VPN config (*.zov);;All Files (*.*)"));

	if (!vpnconfigFile.isEmpty()) {
		Settings::instance()->setLastAccessPath(QFileInfo(vpnconfigFile).absolutePath());
		spinner->start(); // start spinning
		GenericResult result = configMgrProxy->restore(vpnconfigFile, false);
		spinner->stop();

		int id = result.getAttribute(GenericResult::VPN_CONFIG_ID).toInt();
		// code == 2 表示配置存在
		if (result.getCode() == 2) {
			if (isConnectionActive(id)) {
				MessageBoxUtil::error(this, tr("Import VPN config"), tr("Have active connection, disconnected please."));
				return;
			} else if (MessageBoxUtil::confirm(this, tr("Override VPN config"), tr("VPN config exist, Override?"))) {
				result = configMgrProxy->restore(vpnconfigFile, true);
			}
		}

		if (result.getCode() == 0) { // code == 0 表示保存成功
			loadVPNConfig(id);
		} else {
			MessageBoxUtil::error(this, tr("Import VPN config"), tr("Please affirm file is VPN config file"));
		}
	}
}

void Preferences::exportVPNConfig()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (!configMgrProxy || selecteds_items.size() != 1)
		return;

	const QString vpnconfigFile = QFileDialog::getSaveFileName(this, tr("Select VPN config file"),
		Settings::instance()->getLastAccessPath(), tr("VPN config (*.zov);;All Files (*.*)"));

	if (!vpnconfigFile.isEmpty()) {
		Settings::instance()->setLastAccessPath(QFileInfo(vpnconfigFile).absolutePath());
		VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));

		if (!configMgrProxy->backup(vpn_item->getVPNConfig()->getId(), vpnconfigFile, VPNConfigManagerI::O_Config)) {
			MessageBoxUtil::error(this, tr("Export VPN config"), tr("Please affirm the file can be written"));
		} else {
			MessageBoxUtil::information(this, tr("Export VPN config"),
				tr("Export VPN config") + " " + vpn_item->getVPNConfig()->getName() + " " + tr("success"));
		}
	}
}

void Preferences::editOptions()
{
	OptionDialog dialog(this, OptionDialog::tr("Option dialog"));

	if (dialog.exec() == QDialog::Accepted) {
		QByteArray passphrase;	// 需要时才计算
		QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
		VPNItem *vpn_item = NULL;

		// !!必须先保存用户修改后的选项值
		dialog.saveOption();

#if defined(SELF_LOOP_REPLAY_TEST) && defined(_DEBUG)
		const int durationTime = 60000 + rand() % 60000;
		QTimer::singleShot(durationTime, this, SLOT(selfLoopReplayTest()));
#endif

		// 根据当前选项值, 同步安全信息
		if (Settings::instance()->isSaveCredential())
			passphrase = PassphraseGenerator::generateCredentialPassphrase();

		for (int i = 0; i < root_item->childCount(); ++i) {
			if ((vpn_item = dynamic_cast<VPNItem*>(root_item->child(i)))) {
				VPNContext *vpnContext = vpn_item->getVPNContext();
				VPNAgentI::State state = vpn_item->getState();
				Context localCtx(Context::getDefaultContext());

				if (Settings::instance()->isSaveCredential()) {
					if (state == VPNAgentI::Connected && !vpn_item->getVPNConfig()->isTemporary())
						configMgrProxy->save(*vpn_item->getVPNConfig(), passphrase, VPNConfigManagerI::O_Credentials);
				} else {
					// 如果已连接或正在连接只清理持久保存的安全信息, 内存中的不要清理
					if (state != VPNAgentI::Connected && state != VPNAgentI::Connecting && state != VPNAgentI::Reconnecting)
						vpn_item->clearCredentials();
					if (!vpn_item->getVPNConfig()->isTemporary())
						configMgrProxy->clearCredentials(vpn_item->getVPNConfig()->getId());
				}

				// 同步VPNItem
				localCtx.setAttribute(QLatin1String("LOCAL_UI_EVENT"), QVariant::fromValue(true));
				vpnContext->getVPNObserverI()->notify(state, vpn_item->getVPNTunnel(), localCtx);
			}
		}

		// 同步Action, UI
		on_trvConnections_itemSelectionChanged();
	}
}

void Preferences::on_trvConnections_customContextMenuRequested(const QPoint& pos)
{
	QMenu contextMenu(this);
	VPNItem *vpn_item = dynamic_cast<VPNItem*>(m_ui->trvConnections->itemAt(pos));

	if (vpn_item) {
		contextMenu.addAction(m_ui->actionConnect);
		contextMenu.addAction(m_ui->actionDisconnect);
		contextMenu.addSeparator();

		contextMenu.addAction(m_ui->actionEditVPN);
		contextMenu.addAction(m_ui->actionDeleteVPN);
		contextMenu.addSeparator();

		contextMenu.addAction(m_ui->actionExportVPN);
		contextMenu.addSeparator();

#ifdef ENABLE_INTEGRATION
		contextMenu.addAction(m_ui->actionChangePass);
#endif
		contextMenu.addAction(m_ui->actionClearCredentials);
		contextMenu.addSeparator();

		contextMenu.addAction(m_ui->actionLog);
		contextMenu.addAction(m_ui->actionVPNTunnelDetail);
	} else {
		contextMenu.addAction(m_ui->actionNewVPN);
		contextMenu.addSeparator();
		contextMenu.addAction(m_ui->actionImportVPN);
	}

	contextMenu.exec(m_ui->trvConnections->mapToGlobal(pos));
}

void Preferences::showPreferences()
{
	this->show();
	this->setFocus();
	this->activateWindow();
}

void Preferences::showAccessibleResources()
{
	accResDlg->show();
	accResDlg->setFocus();
	accResDlg->activateWindow();

	QEvent e(QEvent::LanguageChange);
	accResDlg->changeEvent(&e);
}

void Preferences::changeLanguage(QAction *action)
{
	if (action) {
		const QString language = action->data().toString();
		if (language.compare(Settings::instance()->getLanguage(), Qt::CaseInsensitive) != 0) {
			SingleApplication *app = dynamic_cast<SingleApplication*>(QApplication::instance());
			app->changeLanguage(language);
			miscSrvProxy->changeLanguage(language);
			Settings::instance()->setLanguage(language);
		}
	}
}

void Preferences::changeUserPassword()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (selecteds_items.size() != 1)
		return;

	// FIXME
	QString reason = tr("FIXME, unimplemented!");
	MessageBoxUtil::error(this, tr("Change password"), tr("Change password fail") + ", " + reason);
}

#if defined(ENABLE_GUOMI)
void Preferences::changeDevicePIN()
{
	// 初始化ChangePINDialog可能时间较长
	QApplication::setOverrideCursor(Qt::WaitCursor);
	ChangePINDialog dialog(this, ChangePINDialog::tr("Change encrypt device PIN"));
	QApplication::restoreOverrideCursor();

	if (dialog.exec() == QDialog::Accepted) {
		int retryCount = 10;
		bool result = false;

		spinner->start(); // start spinning
		result = EncryptDeviceManager::instance()->changeDevicePIN(dialog.getProviderName(), dialog.getContainerPath(),
			dialog.getOldPIN(), dialog.getNewPIN(), &retryCount);
		spinner->stop(); // start spinning

		if (result) {
			// 同步缓存
			synchronizePin(dialog.getProviderName(), dialog.getApplicationPath(), dialog.getNewPIN());
			MessageBoxUtil::information(this, tr("Change PIN"), tr("Encrypt device change pin success"));
		}
		else
			MessageBoxUtil::error(this, tr("Change PIN"),
				tr("Encrypt device change pin fail, remain retry count=") + QString::number(retryCount));
	}
}
#endif

void Preferences::clearCredentials()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (!configMgrProxy || selecteds_items.size() != 1)
		return;

	if (MessageBoxUtil::confirm(this, tr("Credential"), tr("Do you want to remove All Credential?"))) {
		VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));

		// 清理缓存的认证信息
		vpn_item->clearCredentials();

		// 无效清理Action
		m_ui->actionClearCredentials->setEnabled(false);

		// 清理保存的认证信息
		if (Settings::instance()->isSaveCredential() && !vpn_item->getVPNConfig()->isTemporary())
			configMgrProxy->clearCredentials(vpn_item->getVPNConfig()->getId());
	}
}

void Preferences::viewLog()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (selecteds_items.size() != 1)
		return;

	VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));
	vpnLogDlg->setVPNItem(vpn_item);

	if (!vpnLogDlg->isVisible()) {
		vpnLogDlg->showNormal();
		vpnLogDlg->resize(600, 400);
		vpnLogDlg->hide();
	}

	vpnLogDlg->show();
	vpnLogDlg->setFocus();
	vpnLogDlg->activateWindow();

	// 	发送LanguageChange事件放在日志对话框显示之后
	QEvent e(QEvent::LanguageChange);
	vpnLogDlg->changeEvent(&e);

	// setWindowTitle(...), 必须在处理LanguageChange更改事件后
	QString title = VPNLogDialog::tr("VPN log");
	title.append(QLatin1String(" (")).append(vpn_item->getVPNConfig()->getName()).append(QLatin1String(")"));

	vpnLogDlg->setWindowTitle(title);

	QTimer::singleShot(50, vpnLogDlg, SLOT(loadVPNLog()));
}

void Preferences::viewVPNTunnelDetail()
{
	QList<QTreeWidgetItem *> selecteds_items = m_ui->trvConnections->selectedItems();
	if (selecteds_items.size() != 1)
		return;

	VPNItem *vpn_item = dynamic_cast<VPNItem*>(selecteds_items.at(0));

	VPNTunnelDetail tunnelDetail(this, VPNTunnelDetail::tr("VPN tunnel detail"), vpn_item);

	tunnelDetail.exec();
}

void Preferences::manageCertificates()
{
	// 初始化ManageCertificate可能时间较长
	QApplication::setOverrideCursor(Qt::WaitCursor);
	ManageCertificate mgrCertDlg(this, ManageCertificate::tr("Manage certificate"));
	QApplication::restoreOverrideCursor();

	mgrCertDlg.exec();
}

#ifdef SELF_LOOP_REPLAY_TEST
void Preferences::selfLoopReplayTest()
{
	QTreeWidgetItem *root_item = m_ui->trvConnections->invisibleRootItem();
	VPNItem *vpn_item = NULL;

	while (true) {
		bool actived = false;
		for (int i = 0; i < root_item->childCount(); ++i) {
			vpn_item = dynamic_cast<VPNItem*>(root_item->child(i));
			if (vpn_item) {
				VPNAgentI::State state = vpn_item->getState();
				if (state == VPNAgentI::Connecting || state == VPNAgentI::Connected || state == VPNAgentI::Reconnecting) {
					actived = true;
					disconnectVPNImpl(vpn_item, true);
				} else if (state == VPNAgentI::Disconnecting)
					actived = true;
			}
		}

		if (actived) {
			int x = 0;
			while (x < 1000) {
				QApplication::processEvents();
				QThread::msleep(50); x += 50;
			}
		} else
			break;
	}
	for (int j = 0; j < 100; ++j) {
		QApplication::processEvents();
		QThread::msleep(50);
	}

	static int global_loop = 0;
	int y = root_item->childCount() <= 0 ? 0 : global_loop++ % root_item->childCount();

	if (y >= 0 && y < root_item->childCount()) {
		vpn_item = dynamic_cast<VPNItem*>(root_item->child(y));
		if (vpn_item) {
			VPNAgentI::State state = vpn_item->getState();
			if (state == VPNAgentI::ReadyToConnect || state == VPNAgentI::Disconnected) {
				Context localCtx(Context::getDefaultContext());
				localCtx.setAttribute(Context::TRUNC_VPN_LOG, QVariant::fromValue(true));

				if (prepareConnectVPNImpl(vpn_item, localCtx))
					connectVPNImpl(vpn_item, localCtx);
			}
		}
	}

#if defined(SELF_LOOP_REPLAY_TEST) && defined(_DEBUG)
	const int durationTime = 60000 + rand() % 60000;
	QTimer::singleShot(durationTime, this, SLOT(selfLoopReplayTest()));
#endif
}
#endif
