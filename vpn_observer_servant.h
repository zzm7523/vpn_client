#ifndef __VPN_OBSERVER_SERVANT_H__
#define __VPN_OBSERVER_SERVANT_H__

#include "config/config.h"

#include <QWidget>
#include <QString>
#include <QList>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "common/vpn_config.h"
#include "common/vpn_edge.h"
#include "common/vpn_statistics.h"
#include "common/accessible_resource.h"
#include "common/vpn_i_skeleton.h"
#include "common/vpn_config_manager_i_proxy.h"
#include "common/tapdriver_manager_i_proxy.h"

class Preferences;
class VPNItem;

class VPNObserverServant: public QObject, public VPNObserverSkeleton
{
	Q_OBJECT
public:
	VPNObserverServant(Preferences *preferences, const QString& uniqueIdentify, VPNItem *vpn_item,
		VPNConfigManagerProxy *configMgrProxy, TapDriverManagerProxy *tapDrvMgrProxy);

	virtual void notify(VPNAgentI::Warning warning, const QString& reason, const Context& ctx);
	virtual void notify(VPNAgentI::Error error, const QString& reason, const Context& ctx);
	virtual void notify(VPNAgentI::State state, const VPNTunnel& tunnel, const Context& ctx);

	virtual void notify(const QString& message, const Context& ctx);
	virtual void notify(const VPNEdge& edge, const Context& ctx);
	virtual void notify(const QList<AccessibleResource>& accessibleResources, const Context& ctx);
	virtual void notify(const VPNStatistics& statistics, const Context& ctx);

signals:
	void stateChanged(VPNAgentI::State state, VPNItem *vpn_item);
	void edgeChanged(VPNItem *vpn_item);
	void accessibleResourcesChanged(VPNItem *vpn_item);
	void statisticsChanged(VPNItem *vpn_item);

private:
	Q_INVOKABLE void doNotAvailableTAP(const Context& ctx);
	Q_INVOKABLE void doTerminalBind(const Context& ctx);
	bool checkNotifyExpire(VPNAgentI::State state, const Context& ctx);

	VPNItem *vpn_item;
	VPNConfigManagerProxy *configMgrProxy;
	TapDriverManagerProxy *tapDrvMgrProxy;

	VPNAgentI::Error error;
	QString errorReason;
	bool initializationSequenceCompleted;

};

#endif
