#ifndef __VPN_I_H__
#define __VPN_I_H__

#include "../config/config.h"

#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QList>
#include <QDataStream>
#include <QHostAddress>

#include "common.h"
#include "context.h"
#include "generic_result.h"
#include "vpn_edge.h"
#include "accessible_resource.h"
#include "vpn_statistics.h"
#include "server_endpoint.h"
#include "x509_certificate_info.h"

#ifdef _DEBUG
//#define VPN_LOCAL_HOST	QHostAddress("192.168.31.29")
#endif
#ifndef VPN_LOCAL_HOST
#define VPN_LOCAL_HOST	QHostAddress::LocalHost
#endif
#define VPN_SERVICE_PORT  17054

class PolicyEngineI;
class ApplyResult;
class VPNInputAgentI;
class VPNObserverI;

/* 当前隧道信息 */
class VPNTunnel
{
public:
	enum TunDeviceType
	{
		TAP = 0,
		TUN
	};

	enum CompressionOption
	{
		ADAPTIVE = 0,
		YES,
		NO
	};

	VPNTunnel();

	bool isEmpty() const;
	void clear();
	QString format(const QString& prefix, const QString& separator) const;

	const QDateTime& getEstablishedTime() const;
	void setEstablishedTime(const QDateTime& establishedTime);

	const QStringList& getOpenedEncryptDevices() const;
	void setOpenedEncryptDevices(const QStringList& deviceList);

	const QString& getTLSVersion() const;
	void setTLSVersion(const QString& tlsVersion);

	const QString& getTLSCipher() const;
	void setTLSCipher(const QString& tlsCipher);

	const QString& getCipher() const;
	void setCipher(const QString& cipher);

	const QString& getAuth() const;
	void setAuth(const QString& auth);

	int getFragment() const;
	void setFragment(int fragment);

	VPNTunnel::CompressionOption getCompressionOption() const;
	void setCompressionOption(VPNTunnel::CompressionOption compression);

	VPNTunnel::TunDeviceType getTunDeviceType() const;
	void setTunDeviceType(VPNTunnel::TunDeviceType tunDeviceType);

	const QString& getTunDeviceName() const;
	void setTunDeviceName(const QString& tunDeviceName);

#ifdef _WIN32
	unsigned long getTunDeviceIndex() const;
	void setTunDeviceIndex(unsigned long tunDeviceIndex);
#endif

	const QString& getVirtualIPv4Gateway() const;
	void setVirtualIPv4Gateway(const QString& virtualIPv4Gateway);

	const QString& getVirtualIPv6Gateway() const;
	void setVirtualIPv6Gateway(const QString& virtualIPv6Gateway);

	const QString& getVirtualIPv4Addr() const;
	void setVirtualIPv4Addr(const QString& virtualIPv4Addr);

	const QString& getVirtualIPv6Addr() const;
	void setVirtualIPv6Addr(const QString& virtualIPv6Addr);

	const QPair<int, int>& getKeepAlive() const;
	void setKeepAlive(const QPair<int, int>& keepAlive);

	const ServerEndpoint& getServerEndpoint() const;
	void setServerEndpoint(const ServerEndpoint& serverEndpoint);

private:
	friend QDataStream& operator<<(QDataStream& stream, const VPNTunnel& tunnel);
	friend QDataStream& operator>>(QDataStream& stream, VPNTunnel& tunnel);

	QDateTime establishedTime;

	QStringList deviceList;

	QString tlsVersion;
	QString tlsCipher;

	QString cipher;
	QString auth;
	int fragment;
	VPNTunnel::CompressionOption compression;

	VPNTunnel::TunDeviceType tunDeviceType;
	QString tunDeviceName;
	unsigned long tunDeviceIndex;

	QString virtualIPv4Gateway;
	QString virtualIPv6Gateway;
	QString virtualIPv4Addr;
	QString virtualIPv6Addr;
	QPair<int, int> keepAlive;

	ServerEndpoint serverEndpoint;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};
Q_DECLARE_METATYPE(VPNTunnel)

class VPNAgentI
{
public:
	// 定义VPN可能处于的状态
	enum State
	{
		ReadyToConnect = 0,
		Connecting,
		Connected,
		Reconnecting,
		Disconnecting,
		Disconnected
	};

	// 定义VPN各种警告类型
	enum Warning
	{
		NoWarning = 0,
		StateWarning,
		PolicyWarning
	};

	// 定义VPN各种错误类型
	enum Error
	{
		NoError = 0,
		CrashError,	// OpenVPN进程崩溃
		ConnectionError,
		TLSAuthError,
		TLSError,
		CertError,	// 发生证书错误时, 要求用户重新选择证书
		PINError,
		ProxyAuthError,
		AuthError,
		PolicyError,
		NotAvailableTAP,
		ParameterError,
		OtherError
	};

	VPNAgentI();
	virtual ~VPNAgentI();

	virtual bool initialize(const QString& configDirectory, const QString& workingDirectory, const Context& ctx) = 0;
	virtual void clear(const Context& ctx) = 0;

	virtual bool registerPolicyEngine(const QHostAddress& hostAddress, quint16 port, const QString& engineUniqueIdentify,
		const Context& ctx) = 0;
	virtual void unregisterPolicyEngine(const Context& ctx) = 0;

	virtual bool registerObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx) = 0;
	virtual void unregisterObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx) = 0;

	virtual bool registerInputAgent(const QHostAddress& hostAddress, quint16 port, const QString& inputAgentUniqueIdentify,
		const Context& ctx) = 0;
	virtual void unregisterInputAgent(const Context& ctx) = 0;

	virtual void connect(const ServerEndpoint& remote, const QStringList& params, const Context& ctx) = 0;
	virtual void disconnect(const Context& ctx) = 0;

};
Q_DECLARE_METATYPE(VPNAgentI*)

class VPNInputAgentI
{
public:
	enum TrustOption
	{
		None = 0,
		Trust,
		Reject
	};

	virtual ~VPNInputAgentI() {}

	virtual VPNInputAgentI::TrustOption trustServerCertificate(const QStringList& x509Chain, const Context& ctx) = 0;
	virtual X509CertificateInfo chooseClientCertificate(const QString& tlsVersion, const QStringList& keyTypes,
		const QStringList& issuers, const Context& ctx) = 0;

	virtual QByteArray getPrivateKeyPassword(const Context& ctx) = 0;
	virtual QByteArray getPrivateKeyEncrypt(const QString& plaintext, const Context& ctx) = 0;

	virtual QString getUserName(const Context& ctx) = 0;
	virtual QString getPassword(const Context& ctx) = 0;
	virtual QString getOtp(const Context& ctx) = 0;

	virtual QString getProxyUserName(const Context& ctx) = 0;
	virtual QString getProxyPassword(const Context& ctx) = 0;

	virtual bool isCanceled(const Context& ctx) = 0;

};

class VPNObserverI
{
public:
	virtual ~VPNObserverI() {}

	virtual void notify(VPNAgentI::Warning warning, const QString& reason, const Context& ctx) = 0;
	virtual void notify(VPNAgentI::Error error, const QString& reason, const Context& ctx) = 0;
	virtual void notify(VPNAgentI::State state, const VPNTunnel& tunnel, const Context& ctx) = 0;

	virtual void notify(const QString& messagge, const Context& ctx) = 0;
	virtual void notify(const VPNEdge& edge, const Context& ctx) = 0;
	virtual void notify(const QList<AccessibleResource>& accessibleResources, const Context& ctx) = 0;
	virtual void notify(const VPNStatistics& statistics, const Context& ctx) = 0;

};

#endif
