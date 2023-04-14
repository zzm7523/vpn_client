#ifndef __VPN_ITEM_H__
#define __VPN_ITEM_H__

#include "config/config.h"

#include "common/vpn_config.h"
#include "vpn_context.h"

#include <QTreeWidgetItem>

class VPNItem : public QTreeWidgetItem
{
public:
	VPNItem(QTreeWidgetItem *parent, VPNContext *context, VPNConfig *config);
	~VPNItem();

	VPNContext* getVPNContext() const;

	VPNConfig* getVPNConfig() const;

	const VPNEdge& getVPNEdge() const;
	void setVPNEdge(const VPNEdge& edge);

	qint64 getConnectSequence() const;
	void setConnectSequence(const qint64 connectSequence);

	VPNAgentI::State getState() const;
	void setState(VPNAgentI::State state);

	const VPNTunnel& getVPNTunnel() const;
	void setVPNTunnel(const VPNTunnel& tunnel);

	const QList<AccessibleResource>& getAccessibleResources() const;
	void setAccessibleResources(const QList<AccessibleResource>& accessibleResources);

	const VPNStatistics& getVPNStatistics() const;
	void setVPNStatistics(const VPNStatistics& statistics);

	bool isReselectCertificate() const;
	void setReselectCertificate(bool flag);

	bool isReinputProxyPassword() const;
	void setReinputProxyPassword(bool flag);

	bool isReinputPassword() const;
	void setReinputPassword(bool flag);

	int incAndGetProxyAuthPasswordNum();
	int getAndSetProxyAuthPasswordNum(int proxyAuthPasswordNum);

	int incAndGetAuthPasswordNum();
	int getAndSetAuthPasswordNum(int authPasswordNum);

	void clearCredentials();
	void removeCredentials(Credentials::TypeOptions types);

private:
	VPNContext *context;
	VPNConfig *config;

	qint64 connectSequence;
	VPNAgentI::State state;
	VPNEdge edge;
	VPNTunnel tunnel;
	QList<AccessibleResource> accessibleResources;
	VPNStatistics statistics;

	bool reselectCertificate;
	bool reinputProxyPassword;
	bool reinputPassword;
	int proxyAuthPasswordNum;
	int authPasswordNum;
	
};

#endif
