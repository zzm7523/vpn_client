#ifndef __VPN_CONFIG_MANAGER_I_H__
#define __VPN_CONFIG_MANAGER_I_H__

#include "../config/config.h"

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QList>

#include "common.h"
#include "context.h"
#include "generic_result.h"
#include "vpn_config.h"

class VPNConfigManagerI
{
public:
	enum OptionFlag
	{
		O_All = 0,
		O_Config,
		O_Credentials
	};

	virtual ~VPNConfigManagerI() {}

	virtual bool load(const QString& baseSavePath, const QByteArray& passphrase, bool loadCreds, const Context& ctx) = 0;
	virtual void unload(const Context& ctx) = 0;

	virtual bool backup(qint32 id, const QString& filename, VPNConfigManagerI::OptionFlag flag, const Context& ctx) = 0;
	virtual GenericResult restore(const QString& filename, bool forceCover, const Context& ctx) = 0;

	virtual qint32 save(const VPNConfig& config, const QByteArray& passphrase, VPNConfigManagerI::OptionFlag flag,
		const Context& ctx) = 0;
	virtual bool remove(qint32 id, const Context& ctx) = 0;

	virtual bool clearCredentials(qint32 id, const Context& ctx) = 0;

	virtual VPNConfig get(qint32 id, const Context& ctx) = 0;
	virtual VPNConfig get(const QString& name, const Context& ctx) = 0;
	virtual VPNConfig get(const QString& host, quint16 port, const QString& protocol, const Context& ctx) = 0;

	virtual QList<VPNConfig> list(const Context& ctx) const = 0;

};

#endif
