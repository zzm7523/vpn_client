#ifndef _VPN_I_PROXY_H__
#define _VPN_I_PROXY_H__

#include "../config/config.h"

#include "proxy.h"
#include "vpn_i.h"

class VPNAgentProxy : public Proxy, public VPNAgentI
{
	Q_OBJECT
public:
	VPNAgentProxy(const QString& uniqueIdentify, TcpConnection *connection);

	virtual bool initialize(const QString& configDirectory, const QString& workingDirectory,
		const Context& ctx = Context::getDefaultContext());
	virtual void clear(const Context& ctx = Context::getDefaultContext());

	virtual bool registerPolicyEngine(const QHostAddress& hostAddress, quint16 port, const QString& engineUniqueIdentify,
		const Context& ctx = Context::getDefaultContext());
	virtual void unregisterPolicyEngine(const Context& ctx = Context::getDefaultContext());

	virtual bool registerObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx = Context::getDefaultContext());
	virtual void unregisterObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx = Context::getDefaultContext());

	virtual bool registerInputAgent(const QHostAddress& hostAddress, quint16 port, const QString& inputAgentUniqueIdentify,
		const Context& ctx = Context::getDefaultContext());
	virtual void unregisterInputAgent(const Context& ctx = Context::getDefaultContext());

	virtual void connect(const ServerEndpoint& remote, const QStringList& params,
		const Context& ctx = Context::getDefaultContext());
	virtual void disconnect(const Context& ctx = Context::getDefaultContext());

};

class VPNInputAgentProxy : public Proxy, public VPNInputAgentI
{
	Q_OBJECT
public:
	VPNInputAgentProxy(const QString& uniqueIdentify, TcpConnection *connection);

	virtual VPNInputAgentProxy::TrustOption trustServerCertificate(const QStringList& x509Chain,
		const Context& ctx = Context::getDefaultContext());
	virtual X509CertificateInfo chooseClientCertificate(const QString& tlsVersion, const QStringList& keyTypes,
		const QStringList& issuers, const Context& ctx = Context::getDefaultContext());

	virtual QByteArray getPrivateKeyPassword(const Context& ctx = Context::getDefaultContext());
	virtual QByteArray getPrivateKeyEncrypt(const QString& plaintext, const Context& ctx = Context::getDefaultContext());

	virtual QString getUserName(const Context& ctx = Context::getDefaultContext());
	virtual QString getPassword(const Context& ctx = Context::getDefaultContext());
	virtual QString getOtp(const Context& ctx = Context::getDefaultContext());

	virtual QString getProxyUserName(const Context& ctx = Context::getDefaultContext());
	virtual QString getProxyPassword(const Context& ctx = Context::getDefaultContext());

	virtual bool isCanceled(const Context& ctx = Context::getDefaultContext());

};

class VPNObserverProxy: public Proxy, public VPNObserverI
{
	Q_OBJECT
public:
	VPNObserverProxy(const QString& uniqueIdentify, TcpConnection *connection);

public slots:
	virtual void notify(VPNAgentI::Warning warning, const QString& reason, const Context& ctx = Context::getDefaultContext());
	virtual void notify(VPNAgentI::Error error, const QString& reason, const Context& ctx = Context::getDefaultContext());
	virtual void notify(VPNAgentI::State state, const VPNTunnel& tunnel, const Context& ctx = Context::getDefaultContext());

	virtual void notify(const QString& message, const Context& ctx = Context::getDefaultContext());
	virtual void notify(const VPNEdge& edge, const Context& ctx = Context::getDefaultContext());
	virtual void notify(const QList<AccessibleResource>& accessibleResources, const Context& ctx = Context::getDefaultContext());
	virtual void notify(const VPNStatistics& statistics, const Context& ctx = Context::getDefaultContext());

private:
	void doNotify(Request *request);

};

#endif
