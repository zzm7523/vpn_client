#ifndef __VPN_CONFIG_MANAGER_I_PROXY_H__
#define __VPN_CONFIG_MANAGER_I_PROXY_H__

#include "../config/config.h"
#include "proxy.h"
#include "vpn_config_manager_i.h"

class VPNConfigManagerProxy : public Proxy, public VPNConfigManagerI
{
	Q_OBJECT
public:
	VPNConfigManagerProxy(const QString& uniqueIdentify, TcpConnection *connection);

	virtual bool load(const QString& baseSavePath, const QByteArray& passphrase, bool loadCreds,
		const Context& ctx = Context::getDefaultContext());
	virtual void unload(const Context& ctx = Context::getDefaultContext());

	virtual bool backup(qint32 id, const QString& filename, VPNConfigManagerI::OptionFlag flag,
		const Context& ctx = Context::getDefaultContext());
	virtual GenericResult restore(const QString& filename, bool forceCover,
		const Context& ctx = Context::getDefaultContext());

	virtual qint32 save(const VPNConfig& config, const QByteArray& passphrase,
		VPNConfigManagerI::OptionFlag flag, const Context& ctx = Context::getDefaultContext());
	virtual bool remove(qint32 id, const Context& ctx = Context::getDefaultContext());

	virtual bool clearCredentials(qint32 id, const Context& ctx = Context::getDefaultContext());

	virtual VPNConfig get(qint32 id, const Context& ctx = Context::getDefaultContext());
	virtual VPNConfig get(const QString& name, const Context& ctx = Context::getDefaultContext());
	virtual VPNConfig get(const QString& host, quint16 port, const QString& protocol,
		const Context& ctx = Context::getDefaultContext());

	virtual QList<VPNConfig> list(const Context& ctx = Context::getDefaultContext()) const;

};

#endif
