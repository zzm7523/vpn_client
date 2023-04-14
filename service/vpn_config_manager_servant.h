#ifndef __VPN_CONFIG_MANAGER_SERVANT_H__
#define __VPN_CONFIG_MANAGER_SERVANT_H__

#include "../config/config.h"

#include <QStringList>
#include <QList>
#include <QDir>

#include "../common/vpn_config_manager_i_proxy.h"
#include "../common/vpn_config_manager_i_skeleton.h"

class VPNConfigManagerServant : public QObject, public VPNConfigManagerSkeleton
{
	Q_OBJECT
public:
	explicit VPNConfigManagerServant(const QString& uniqueIdentify);

	virtual bool load(const QString& baseSavePath, const QByteArray& passphrase, bool loadCreds, const Context& ctx);
	virtual void unload(const Context& ctx);

	virtual bool backup(qint32 id, const QString& filename, VPNConfigManagerI::OptionFlag flag, const Context& ctx);
	virtual GenericResult restore(const QString& filename, bool forceCover, const Context& ctx);

	virtual qint32 save(const VPNConfig& config, const QByteArray& passphrase, VPNConfigManagerI::OptionFlag flag,
		const Context& ctx);
	virtual bool remove(qint32 id, const Context& ctx);

	virtual bool clearCredentials(qint32 id, const Context& ctx);

	virtual VPNConfig get(qint32 id, const Context& ctx);
	virtual VPNConfig get(const QString& name, const Context& ctx);
	virtual VPNConfig get(const QString& host, quint16 port, const QString& protocol, const Context& ctx);

	virtual QList<VPNConfig> list(const Context& ctx) const;

private:
	qint32 generateVPNConfigId();
	bool createAdvConfigFile(const QDir& configDir) const;
	bool createLogFile(const QDir& configDir) const;
	bool truncEdgeFile(const QDir& configDir) const;
	bool loadVPNConfig(const QString& configPath, const QByteArray& passphrase, bool loadCreds, VPNConfig& config);
	bool saveVPNConfig(const QString& fileName, VPNConfig& config);
	bool saveTLSAuthFile(VPNConfig& config);
	bool saveCrediantials(const QString& fileName, const QByteArray& passphrase, VPNConfig& config);
	bool parseOptionLine(const QString& line, QStringList& params);
	bool readVPNConfig(const QString& fileName, VPNConfig& config);
	bool readCrediantials(const QString& fileName, const QByteArray& passphrase, VPNConfig& config);

	qint32 nextConfigId;
	bool loaded;
	QString baseSavePath;
	QList<VPNConfig> configList;

};

#endif
