#ifndef __VPN_CONFIG_H__
#define __VPN_CONFIG_H__

#include "../config/config.h"

#include <QStringList>
#include <QDataStream>

#include "server_endpoint_selector.h"
#include "tls_auth.h"
#include "credentials.h"

class VPNConfig
{
public:
	enum AuthOptionFlag
	{
		NoneOption  = 0x0,
		AutoProbe   = 0x0001,	// ȱʡ�Զ�̽��
		EnablePassword  = 0x0002,
		DisablePassword = 0x0004
	};
	Q_DECLARE_FLAGS(AuthOptions, AuthOptionFlag)

	enum ProxyType
	{
		NoneProxy = 0,
		System,
		Http,
		Socks
	};

	VPNConfig(qint32 id, const QString& path);
	VPNConfig();
	// ȱʡ�������캯���Ϳ�����

	void clear();
	bool isEmpty() const;

	// VPNConfigΨһ��ʾ, ����Ŀ¼��
	qint32 getId() const;
	void setId(qint32 id);

	// ��ʱ���õ�����Ϊ��
	const QString& getName() const;
	void setName(const QString& name);

	// ���ô洢·��
	const QString& getPath() const;
	void setPath(const QString& path);

	const QString& getX509UserNameField() const;
	void setX509UserNameField(const QString& x509UserNameField);

	bool isTemporary() const;
	void setTemporary(bool temporary);

	bool isAutoReconnect();
	void setAutoReconnect(bool autoReconnect);

	bool isAutoStart() const;
	void setAutoStart(bool autoStart);

	VPNConfig::AuthOptions getAuthOptions() const;
	void setAuthOptions(VPNConfig::AuthOptions authOption);

	const QList<ServerEndpoint>& getServerEndpoints() const;
	void setServerEndpoints(const QList<ServerEndpoint>& remotes);

	const QString& getTlsVersion() const;
	void setTlsVersion(const QString& tlsVersion);

	const QString& getCipher() const;
	void setCipher(const QString& cipher);

	const QString& getAuth() const;
	void setAuth(const QString& auth);

	TLSAuth& getTLSAuth();
	void setTLSAuth(const TLSAuth& tlsAuth);

	bool isEnableProxy() const;
	void setEnableProxy(bool enableProxy);

	VPNConfig::ProxyType getProxyType() const;
	void setProxyType(VPNConfig::ProxyType proxyType);

	const QString& getProxyHost() const;
	void setProxyHost(const QString& proxyHost);

	quint16 getProxyPort() const;
	void setProxyPort(quint16 proxyPort);

	const QString& getCompatibleOption();
	void setCompatibleOption(const QString& compatibleOption);

	Credentials& getCredentials();

	bool operator == (const VPNConfig& other) const;
	bool operator < (const VPNConfig& other) const;

private:
	friend QDataStream& operator<<(QDataStream& stream, const VPNConfig& config);
	friend QDataStream& operator>>(QDataStream& stream, VPNConfig& config);

	qint32 id;
	QString name;
	QString path;

	QString x509UserNameField;
	// temporary, autoReconnect ����ʱʹ��, ��Ҫ���浽�ļ�
	bool temporary;
	bool autoReconnect;
	bool autoStart;
	VPNConfig::AuthOptions authOptions;

	QList<ServerEndpoint> remotes;
	QString tlsVersion;
	QString cipher;
	QString auth;
	TLSAuth tlsAuth;

	bool enableProxy;
	VPNConfig::ProxyType proxyType;
	QString proxyHost;
	quint16 proxyPort;

	QString compatibleOption;
	Credentials credentials;

	// ÿ�����serial_uid����ͬ
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(VPNConfig)
Q_DECLARE_OPERATORS_FOR_FLAGS(VPNConfig::AuthOptions)

#endif
