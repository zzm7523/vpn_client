#ifndef __VPN_LOG_PARSER_H__
#define __VPN_LOG_PARSER_H__

#include "../config/config.h"

#include <QString>
#include <QByteArray>
#include <QStringList>

#include "../common/vpn_i.h"

class VPNLogParser
{
public:
	/* openvpn.exe所有输入输出都采用UTF-8编码 */
	explicit VPNLogParser(const QByteArray& output);

	bool hasTLSStartHelloFailed() const;
	bool hasTLSKeyNegotiateFailed() const;
	bool hasTunnelNegotiateError() const;
	bool hasTLSAuthError() const;
	bool hasPrivateKeyPasswordVerifyError() const;
	bool hasProxyAuthError() const;
	bool hasAuthError() const;
	bool hasNeedPEMpass() const;
	bool hasUnknownCA() const;
	bool hasTLSError() const;
	bool hasClientCertificateRevoked() const;
	bool hasClientCertificateExpired() const;
	bool hasClientCertificateIsNotYetValid() const;
	bool hasCannotLoadCertificate() const;
	bool hasUnableGetIssuerCert() const;
	bool hasProxyRequireAuthentication() const;
	bool hasAllTAPUsed() const;
	bool hasNoTAP() const;
	bool hasUnsupportedCipher() const;
	bool hasUnsupportedAuth() const;
	bool hasDecryptError() const;
	bool hasCannotResolveHostAddress() const;
	bool hasMacVerifyFailure() const;
	bool hasParameterError() const;
	bool hasConnectionError() const;
	bool hasSigTermReceived() const;
	bool hasFatalError() const;

	bool requestTrustServerCertificate() const;
	bool requestClientCertificate() const;
	bool requestPrivateKeyPassword() const;
	bool requestPrivateKeyEncrypt() const;
	bool requestUsername() const;
	bool requestPassword() const;
	bool requestProxyUsername() const;
	bool requestProxyPassword() const;
	bool requestPolicyResponse() const;

	bool requestOpenEncryptDevices() const;
	bool requestResolveHost() const;
	bool requestConnectServer() const;
	bool requestClientConfig() const;
	bool requestAssignIPAddress() const;
	bool requestAddRoutes() const;

	bool isOpenEncryptDevices() const;
	bool isPolicy() const;

	bool isTLSDetails() const;
	bool isCipher() const;
	bool isAuth() const;
	bool isFragmentOption() const;
	bool isCompressionOption() const;
	bool isTunDeviceType() const;
	bool isTunDeviceName() const;
#ifdef _WIN32
	bool isTunDeviceIndex() const;
#endif
	bool isVirtualIPv4Gateway() const;
	bool isVirtualIPv4Addr() const;
	bool isVirtualIPv6Addr() const;
	bool isKeepAlive() const;
	bool isInitializationSequenceCompleted() const;
	bool isRestarting() const;

	bool getUnsupportedCipher(QString& cipher);
	bool getUnsupportedAuth(QString& auth);

	bool getOpenedEncryptDevices(VPNTunnel& tunnel);
	bool getPolicys(QStringList& policys);
	bool getTLSVersion(VPNTunnel& tunnel);
	bool getTLSCipher(VPNTunnel& tunnel);
	bool getCipher(VPNTunnel& tunnel);
	bool getAuth(VPNTunnel& tunnel);
	bool getFragmentOption(VPNTunnel& tunnel);
	bool getCompressionOption(VPNTunnel& tunnel);
	bool getTunDeviceType(VPNTunnel& tunnel);
	bool getTunDeviceName(VPNTunnel& tunnel);
	bool getTunDeviceIndex(VPNTunnel& tunnel);
	bool getVirtualIPv4Gateway(VPNTunnel& tunnel);
	bool getVirtualIPv4Addr(VPNTunnel& tunnel);
	bool getVirtualIPv6Addr(VPNTunnel& tunnel);
	bool getKeepAlive(VPNTunnel& tunnel);
	bool getRestartingReason(QString& auth);

	bool getAuthErrorReason(QString& errorReason);
	bool getRetryCount(int *retryCount);
	bool getPrivateKeyEncryptReqeust(QString& encryptReqeust);
	bool getCertificateChain(QStringList& certChain);
	bool getKeyTypes(QStringList& keyTypes);
	bool getIssuers(QStringList& issuers);

private:
	bool extractContents(const QString& text, const QString& beginDelim, const QString& endDelim,
		bool stripDelim, QStringList& contents);

	QString text;

};

#endif
