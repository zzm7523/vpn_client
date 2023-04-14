#include <QApplication>
#include <QTimer>
#include <QDateTime>
#include <QSysInfo>

#include "common/common.h"
#include "common/tapdriver_manager.h"
#include "common/message_box_util.h"
#include "common/passphrase_generator.h"
#include "common/translate.h"
#include "common/encrypt_device_manager.h"
#include "common/vpn_config.h"
#include "common/vpn_i_proxy.h"
#include "common/vpn_config_manager_i_proxy.h"

#include "policy/password_policy.h"
#include "policy/update_policy.h"
#include "policy/resource_policy.h"
#include "policy/cluster_policy.h"
#include "policy/terminal_bind_policy.h"

#include "vpn_observer_servant.h"
#include "settings.h"
#include "vpn_item.h"
#include "preferences.h"

VPNObserverServant::VPNObserverServant(Preferences *preferences, const QString& _uniqueIdentify, VPNItem *_vpn_item,
		VPNConfigManagerProxy *_configMgrProxy, TapDriverManagerProxy *_tapDrvMgrProxy)
	: QObject(preferences), VPNObserverSkeleton(_uniqueIdentify), vpn_item(_vpn_item), configMgrProxy(_configMgrProxy),
	tapDrvMgrProxy(_tapDrvMgrProxy), error(VPNAgentI::NoError), initializationSequenceCompleted(false)
{
}

void VPNObserverServant::notify(VPNAgentI::Error error, const QString& reason, const Context& ctx)
{
	if (!userIdentifyEqual(Context::getDefaultContext(), ctx))
		return;	// ���������û�, ����Ҫ���ദ��, ��������
	
	if (!checkNotifyExpire(vpn_item->getState(), ctx))
		return;	// ֪ͨ�ѹ���, ����Ҫ���ദ��, ��������

	this->error = error; this->errorReason = reason;
	if (VPNAgentI::NoError == error) {
		return;	// ����Ҫ���ദ��, ��������
	}

	Preferences *preferences = qobject_cast<Preferences*>(this->parent());
	VPNContext *vpnContext = vpn_item->getVPNContext();
	bool showError = true, ignoreError = (VPNAgentI::Connected == vpn_item->getState());
	Context localCtx(ctx);

	localCtx.setAttribute(Context::TRUNC_VPN_LOG, QVariant::fromValue(false));

	if (VPNAgentI::CertError == error && !ignoreError) {
		vpn_item->getVPNConfig()->getCredentials().clear();	// �ͻ�֤�����, �������а�ȫ��Ϣ
		if (vpn_item->isReselectCertificate()) {
			vpn_item->setReselectCertificate(false);
			// ��������ɺ�, �����·������ӳ���
			bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
				Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, localCtx));
			Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
			showError = false; ignoreError = true;
		}

	} else if (VPNAgentI::PINError == error && !ignoreError) {
		vpn_item->getVPNConfig()->getCredentials().removeCredentials(Credentials::KeyPassword);

	} else if (VPNAgentI::ProxyAuthError == error && !ignoreError) {
		vpn_item->getVPNConfig()->getCredentials().removeCredentials(Credentials::ProxyPassword);
		if (vpn_item->isReinputProxyPassword() || vpn_item->incAndGetProxyAuthPasswordNum() < MAX_AUTH_PASSWD_NUM) {
			vpn_item->setReinputProxyPassword(false);
			bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
				Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, localCtx));
			Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
			showError = false; ignoreError = true;
		}

	} else if (VPNAgentI::AuthError == error && !ignoreError) {	// �յ�AuthError, ˵�������Ҫ��������֤
		bool terminalBind = localCtx.getAttribute(Context::TERMINAL_BIND).toBool();
		if (terminalBind) {	// Ҫ���ն˰�
			localCtx.removeAttribute(Context::AUTH_ERROR);
			bool result = QMetaObject::invokeMethod(this, "doTerminalBind", Qt::QueuedConnection,
				Q_ARG(Context, localCtx));
			Q_ASSERT_X(result, "doTerminalBind", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
			showError = false; ignoreError = true;

		} else {
			const VPNConfig::AuthOptions authOptions = vpn_item->getVPNConfig()->getAuthOptions();
			if (!(authOptions & VPNConfig::DisablePassword)) {	// δ����������֤
				if (!(authOptions & VPNConfig::EnablePassword)) {
					// �Ȳ�Ҫ��������, ���Ա��������
//					vpn_item->getVPNConfig()->getCredentials().removeCredentials(Credentials::Password);
					vpn_item->getVPNConfig()->setAuthOptions(authOptions | VPNConfig::EnablePassword);
					localCtx.removeAttribute(Context::AUTH_ERROR);
					bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
						Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, localCtx));
					Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
					showError = false; ignoreError = true;

				} else {
					vpn_item->getVPNConfig()->getCredentials().removeCredentials(Credentials::Password);
					if (vpn_item->isReinputPassword() || vpn_item->incAndGetAuthPasswordNum() < MAX_AUTH_PASSWD_NUM) {
						vpn_item->setReinputPassword(false);
						bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
							Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, localCtx));
						Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
						showError = false; ignoreError = true;
					}
				}
			}
		}

	} else if (VPNAgentI::NotAvailableTAP == error && !ignoreError) {	// ��װTap����, Ȼ���ٳ���һ��
		// ��������ɺ�, �Ű�װTAP����, ���·������ӳ���
		bool result = QMetaObject::invokeMethod(this, "doNotAvailableTAP", Qt::QueuedConnection,
			Q_ARG(Context, localCtx));
		Q_ASSERT_X(result, "doNotAvailableTAP", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
//		showError = false; ignoreError = true;

	} else if (VPNAgentI::ConnectionError == error && !ignoreError) {	// ��·����ʱ, ѡ������ServerEndpoint
		QString text = QApplication::translate("VPNAgentI", "Reselect optimal gateway ...");
//		vpn_item->setToolTip(2, text);
		vpn_item->setText(2, text);
		if (vpnContext->getServerEndpointSelector()->select()) {
			bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
				Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, localCtx));
			Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
//			showError = false; ignoreError = true;
		}
	}

	if (showError) {
		QString text = reason.isEmpty() ? Translate::translateVPNState(vpn_item->getState()) : reason;
//		vpn_item->setToolTip(2, text);
		vpn_item->setText(2, text);
	}
	if (ignoreError) {
		this->error = VPNAgentI::NoError;
		this->errorReason.clear();
	}

	if (Settings::instance()->isSaveCredential() &&
			vpn_item->getVPNConfig()->getCredentials().hasAnyCrediantials())
		vpn_item->setIcon(1, QIcon(QLatin1String(":/images/crypted.png")));
	else
		vpn_item->setIcon(1, QIcon());

	if (VPNAgentI::ProxyAuthError == error || VPNAgentI::AuthError == error || VPNAgentI::CertError == error ||
			VPNAgentI::PINError == error) {
		// ��֤����, ���������֤��Ϣ, !!����������
		if (Settings::instance()->isSaveCredential() && !vpn_item->getVPNConfig()->isTemporary())
			configMgrProxy->clearCredentials(vpn_item->getVPNConfig()->getId());
	}
}

void VPNObserverServant::notify(VPNAgentI::Warning warning, const QString& reason, const Context& ctx)
{
	if (!userIdentifyEqual(Context::getDefaultContext(), ctx))
		return;	// ���������û�, ����Ҫ���ദ��, ��������
	
	if (!checkNotifyExpire(vpn_item->getState(), ctx))
		return;	// ֪ͨ�ѹ���, ����Ҫ���ദ��, ��������

	Preferences *preferences = qobject_cast<Preferences*>(this->parent());
	qDebug() << "Warning: warning=" << warning << ", reason=" << reason << "\n";
	preferences->showTrayMessage(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR), reason, QSystemTrayIcon::Warning);
}

void VPNObserverServant::notify(VPNAgentI::State state, const VPNTunnel& tunnel, const Context& ctx)
{
	// ״̬��Ϣ, ������Ҫͬ��

	if (userIdentifyEqual(Context::getDefaultContext(), ctx)) {
		if (!checkNotifyExpire(state, ctx))
			return;	// ֪ͨ�ѹ���, ����Ҫ���ദ��, ��������
	}

	Preferences *preferences = qobject_cast<Preferences*>(this->parent());
	QString text = Translate::translateVPNState(state);
	VPNContext *vpnContext = vpn_item->getVPNContext();
	ServerEndpointSelector *selector = vpnContext->getServerEndpointSelector();
	bool localUiEvent = ctx.getAttribute(QLatin1String("LOCAL_UI_EVENT")).toBool();

	vpn_item->setToolTip(2, QString());
	vpn_item->setState(state);
	vpn_item->setVPNTunnel(tunnel);

	if (VPNAgentI::Disconnected == state || VPNAgentI::ReadyToConnect == state) {
		if (VPNAgentI::ReadyToConnect != state && VPNAgentI::NoError != error && !errorReason.isEmpty())
			text = errorReason;
//		vpn_item->setToolTip(2, text);
		vpn_item->setText(2, text);
		vpn_item->setVPNStatistics(VPNStatistics());	// �������ͳ������

		if (!localUiEvent) {
			if (this->initializationSequenceCompleted) {		// ��ʾballoon��Ϣ
				preferences->showTrayMessage(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR),
					tr("Disconnected from VPN.\nName: ") + vpn_item->getVPNConfig()->getName());

				// �쳣��ֹ, �Զ�������ǰ�ķ�����
				if (vpn_item->getVPNConfig()->isAutoReconnect() && Settings::instance()->isAutoReconnect() &&
						!selector->getServerEndpoint().isEmpty()) {				
					Context localCtx(Context::getDefaultContext());	// ���·�������, ��Ҫ��ctx
					bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
						Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, localCtx));
					Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
				}
			}
		}

		this->initializationSequenceCompleted = false;

	} else if (VPNAgentI::Connected == state) {
//		vpn_item->setToolTip(2, tunnel.format(text + "\n", ", "));
		vpn_item->setText(2, tunnel.format(text + "\n", ", "));

		if (!localUiEvent) {
			// ���ӳɹ�, ��ЧVPN�Զ�����; ���÷�����ѡ����, ����ʱ��ѡ��ǰ�ķ�����
			const ServerEndpoint lastConnected = selector->getServerEndpoint();
			// !! ���ӿ������������̷����, lastConnected�ǿ�
			vpn_item->getVPNConfig()->setAutoReconnect(!lastConnected.isEmpty());

			selector->initialize(vpn_item->getVPNEdge().getClusterAlgorithm(), vpn_item->getVPNConfig()->getServerEndpoints(),
				vpn_item->getVPNEdge().getClusterEndpoints(), lastConnected);
			
			// ��ʾballoon��Ϣ
			preferences->showTrayMessage(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR), tunnel.format(text + "\n", "\n"));

			if (Settings::instance()->isAutoMinimum())
				preferences->hide();

#ifdef ENABLE_INTEGRATION
			if (Settings::instance()->isPopupAccessibleResource())
				preferences->showAccessibleResources();
#endif

			// ���ӳɹ�, ������֤��Ϣ, !!����������
			if (Settings::instance()->isSaveCredential() && !vpn_item->getVPNConfig()->isTemporary()) {
				const QByteArray passphrase = PassphraseGenerator::generateCredentialPassphrase();
				configMgrProxy->save(*vpn_item->getVPNConfig(), passphrase, VPNConfigManagerI::O_Credentials);	
			}
		}

		this->initializationSequenceCompleted = true;

	} else {
		if (VPNAgentI::Connecting == state || VPNAgentI::Disconnecting == state) {		
			errno = VPNAgentI::NoError;	// ������һ�����Ӵ���
			errorReason.clear();
		}
		vpn_item->setText(2, text);
	}

	if (Settings::instance()->isSaveCredential() && vpn_item->getVPNConfig()->getCredentials().hasAnyCrediantials())
		vpn_item->setIcon(1, QIcon(QLatin1String(":/images/crypted.png")));
	else
		vpn_item->setIcon(1, QIcon());

	emit stateChanged(state, vpn_item);	// !!�����ȽϺ�
}

void VPNObserverServant::notify(const QString& messagge, const Context& ctx)
{
	if (!userIdentifyEqual(Context::getDefaultContext(), ctx))
		return;	// ���������û�, ����Ҫ���ദ��, ��������
	
	if (!checkNotifyExpire(vpn_item->getState(), ctx))
		return;	// ֪ͨ�ѹ���, ����Ҫ���ദ��, ��������

	if (VPNAgentI::Connecting == vpn_item->getState() || VPNAgentI::Reconnecting == vpn_item->getState()
			|| VPNAgentI::Disconnecting == vpn_item->getState()) {
		if (!messagge.isEmpty()) {
//			vpn_item->setToolTip(2, messagge);
			vpn_item->setText(2, messagge);
		}
	}
}

void VPNObserverServant::notify(const VPNEdge& edge, const Context& ctx)
{
	if (!userIdentifyEqual(Context::getDefaultContext(), ctx))
		return;	// ���������û�, ����Ҫ���ദ��, ��������
	
	if (!checkNotifyExpire(vpn_item->getState(), ctx))
		return;	// ֪ͨ�ѹ���, ����Ҫ���ദ��, ��������

#ifdef ENABLE_INTEGRATION
	bool updateServiceChanged = false;
	if (vpn_item->getVPNEdge().getUpdateService().compare(edge.getUpdateService(), Qt::CaseInsensitive))
		updateServiceChanged = true;

	vpn_item->setVPNEdge(edge);
	emit edgeChanged(vpn_item);

#ifdef ENABLE_UPDATER
	// �����в������Զ�����, ֻ������ʱ����
	if (Settings::instance()->isCheckUpdate() && updateServiceChanged) {
		QDateTime nextCheckUpdate = Settings::instance()->getLastCheckUpdate();
		nextCheckUpdate = nextCheckUpdate.addDays(1);	// ÿ������Զ�����һ��

		if (QDateTime::currentDateTime() > nextCheckUpdate) {
			Preferences *preferences = qobject_cast<Preferences*>(this->parent());
			QMetaObject::invokeMethod(preferences, "checkForUpdate", Qt::QueuedConnection);
		}
	}
#endif
#endif
}

void VPNObserverServant::notify(const QList<AccessibleResource>& accessibleResources, const Context& ctx)
{
	if (!userIdentifyEqual(Context::getDefaultContext(), ctx))
		return;	// ���������û�, ����Ҫ���ദ��, ��������
	
	if (!checkNotifyExpire(vpn_item->getState(), ctx))
		return;	// ֪ͨ�ѹ���, ����Ҫ���ദ��, ��������

	vpn_item->setAccessibleResources(accessibleResources);
	emit accessibleResourcesChanged(vpn_item);
}

void VPNObserverServant::notify(const VPNStatistics& statistics, const Context& ctx)
{
	if (!userIdentifyEqual(Context::getDefaultContext(), ctx))
		return;	// ���������û�, ����Ҫ���ദ��, ��������
	
	if (!checkNotifyExpire(vpn_item->getState(), ctx))
		return;	// ֪ͨ�ѹ���, ����Ҫ���ദ��, ��������

	vpn_item->setVPNStatistics(statistics);
	emit statisticsChanged(vpn_item);
}

void VPNObserverServant::doNotAvailableTAP(const Context& ctx)
{
#ifdef _WIN32
	Preferences *preferences = qobject_cast<Preferences*>(this->parent());
	bool success = false;

	// XP�޷�ͨ����̨����װTAP����; �ٶ���ǰ�û��ǹ���Ա, ������ǰ�˰�װ
	if (QSysInfo::kernelVersion().startsWith("5") /* < 6*/) {
		TapDriverManager tapDrvMgr;
		tapDrvMgr.initialize(QString(QLatin1String("%1/driver")).arg(QApplication::applicationDirPath()));
		success = tapDrvMgr.installTapDriver();
	}
	else {
		success = tapDrvMgrProxy->installTapDriver();
	}

	if (success) {
		bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
			Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, ctx));
		Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
	}
#else
	Q_UNUSED(ctx)
#endif
}

void VPNObserverServant::doTerminalBind(const Context& ctx)
{
	Preferences *preferences = qobject_cast<Preferences*>(this->parent());
	Context localCtx(ctx);
	ApplyResult result = vpn_item->getVPNContext()->getFrontPolicyEngineI()->applyPolicy(
		TerminalBindPolicy().toExternalForm(), localCtx);

	if (ApplyResult::Success == result.getResult()) {
		bool result = QMetaObject::invokeMethod(preferences, "connectVPNImpl", Qt::QueuedConnection,
			Q_ARG(VPNItem*, vpn_item), Q_ARG(Context, localCtx));
		Q_ASSERT_X(result, "connectVPNImpl", "QMetaObject::invokeMethod(...) fail"); Q_UNUSED(result);
	}
}

bool VPNObserverServant::checkNotifyExpire(VPNAgentI::State state, const Context& ctx)
{
	Q_UNUSED(state)

	if (ctx.hasAttribute(Context::VPN_CONNECT_SEQUENCE)) {
		const qint64 connectSequence = ctx.getAttribute(Context::VPN_CONNECT_SEQUENCE).value<qint64>();
		if (connectSequence < vpn_item->getConnectSequence())	// �ٵ�����ǰ����֪ͨ, ����
			return false;
		else if (connectSequence > vpn_item->getConnectSequence())
			vpn_item->setConnectSequence(connectSequence);	// �����ͻ��˷��������, ͬ���������
	}

	return true;
}
