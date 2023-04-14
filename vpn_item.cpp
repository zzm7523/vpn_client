#include "common/common.h"
#include "common/vpn_config.h"

#include "vpn_item.h"
#include "settings.h"

VPNItem::VPNItem(QTreeWidgetItem *_parent, VPNContext *_context, VPNConfig *_config)
		: QTreeWidgetItem(_parent), context(_context), config(_config), connectSequence(0),
	state(VPNAgentI::ReadyToConnect), reselectCertificate(false), reinputProxyPassword(false),
	reinputPassword(false), proxyAuthPasswordNum(0), authPasswordNum(0)
{    
	if (Settings::instance()->isSaveCredential() && config->getCredentials().hasAnyCrediantials())
		setIcon(1, QIcon(QLatin1String(":/images/crypted.png")));
	else
		setIcon(1, QIcon());
	setText(1, config->getName());
}

VPNItem::~VPNItem()
{
	if (this->config)
		delete this->config;

	if (this->context)
		delete this->context;
}

VPNContext* VPNItem::getVPNContext() const
{
	return this->context;
}

const VPNEdge& VPNItem::getVPNEdge() const
{
	return this->edge;
}

void VPNItem::setVPNEdge(const VPNEdge& edge)
{
	this->edge = edge;
}

VPNConfig* VPNItem::getVPNConfig() const
{
	return this->config;
}

qint64 VPNItem::getConnectSequence() const
{
	return this->connectSequence;
}

void VPNItem::setConnectSequence(const qint64 connectSequence)
{
	this->connectSequence = connectSequence;
}

VPNAgentI::State VPNItem::getState() const
{
	return this->state;
}

void VPNItem::setState(VPNAgentI::State state)
{
	this->state = state;
}

const VPNTunnel& VPNItem::getVPNTunnel() const
{
	return this->tunnel;
}

void VPNItem::setVPNTunnel(const VPNTunnel& tunnel)
{
	this->tunnel = tunnel;
}

const QList<AccessibleResource>& VPNItem::getAccessibleResources() const
{
	return this->accessibleResources;
}

void VPNItem::setAccessibleResources(const QList<AccessibleResource>& accessibleResources) {
	this->accessibleResources = accessibleResources;
}

const VPNStatistics& VPNItem::getVPNStatistics() const
{
	return statistics;
}

void VPNItem::setVPNStatistics(const VPNStatistics& statistics)
{
	this->statistics = statistics;
}

bool VPNItem::isReselectCertificate() const
{
	return this->reselectCertificate;
}

void VPNItem::setReselectCertificate(bool flag)
{
	this->reselectCertificate = flag;
}

bool VPNItem::isReinputProxyPassword() const
{
	return this->reinputProxyPassword;
}

void VPNItem::setReinputProxyPassword(bool flag)
{
	this->reinputProxyPassword = flag;
}

bool VPNItem::isReinputPassword() const
{
	return this->reinputPassword;
}

void VPNItem::setReinputPassword(bool flag)
{
	this->reinputPassword = flag;
}

int VPNItem::incAndGetProxyAuthPasswordNum()
{
	return ++this->proxyAuthPasswordNum;
}

int VPNItem::getAndSetProxyAuthPasswordNum(int proxyAuthPasswordNum)
{
	int z = this->proxyAuthPasswordNum;
	this->proxyAuthPasswordNum = proxyAuthPasswordNum;
	return z;
}

int VPNItem::incAndGetAuthPasswordNum()
{
	return ++this->authPasswordNum;
}

int VPNItem::getAndSetAuthPasswordNum(int authPasswordNum)
{
	int z = this->authPasswordNum;
	this->authPasswordNum = authPasswordNum;
	return z;
}

void VPNItem::clearCredentials()
{
	this->config->getCredentials().clear();
	this->setIcon(1, QIcon());
}

void VPNItem::removeCredentials(Credentials::TypeOptions types)
{
	this->config->getCredentials().removeCredentials(types);
	if (!this->config->getCredentials().hasAnyCrediantials())
		this->setIcon(1, QIcon());
}
