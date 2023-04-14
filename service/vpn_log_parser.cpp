#include <QRegularExpression>
#include <QDebug>
#include <QDateTime>

#include "vpn_log_parser.h"

VPNLogParser::VPNLogParser(const QByteArray& output)
{
	text = QString::fromUtf8(output);	// openvpn.exe输入输出采用UTF-8编码
}

bool VPNLogParser::hasTLSStartHelloFailed() const
{
	// TLS Error: TLS start hello failed to occur within 60 seconds
	return text.contains(QRegularExpression(
		"TLS[\\x20|\\t]+Error:[\\x20|\\t]+TLS[\\x20|\\t]+start[\\x20|\\t]+hello[\\x20|\\t]+failed",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasTLSKeyNegotiateFailed() const
{
	// TLS Error: TLS key negotiation failed to occur within 600 seconds
	return text.contains(QRegularExpression(
		"TLS[\\x20|\\t]+Error:[\\x20|\\t]+TLS[\\x20|\\t]+key[\\x20|\\t]+negotiation[\\x20|\\t]+failed",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasTunnelNegotiateError() const
{
	// Failed to negotiation tunnel cipher algorithm
	return text.contains(QRegularExpression(
		"Failed[\\x20|\\t]+to[\\x20|\\t]+negotiation[\\x20|\\t]+tunnel[\\x20|\\t]+cipher[\\x20|\\t]+algorithm",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasTLSAuthError() const
{
	// cannot locate HMAC in incoming packet
	return text.contains(QRegularExpression(
		"cannot[\\x20|\\t]+locate[\\x20|\\t]+HMAC[\\x20|\\t]+in[\\x20|\\t]+incoming[\\x20|\\t]+packet",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasPrivateKeyPasswordVerifyError() const
{
	// ERROR: Private Key Password verify fail
	return text.contains(QRegularExpression(
		"ERROR:[\\x20|\\t]+Private[\\x20|\\t]+Key[\\x20|\\t]+Password[\\x20|\\t]+verify[\\x20|\\t]+fail",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasProxyAuthError() const
{
	// socks_username_password_auth: TCP port read timeout expired
	// socks_username_password_auth: TCP port read failed on select()
	// socks_username_password_auth: TCP port read failed on recv()
	// socks_username_password_auth: server refused the authentication
	if (text.contains(QRegularExpression("socks_username_password_auth:.+(timeout|failed|refused)[\\x20|\\t]+",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// HTTP proxy returned bad status
	if (text.contains(QRegularExpression("HTTP[\\x20|\\t]+proxy[\\x20|\\t]+returned[\\x20|\\t]+bad[\\x20|\\t]+status",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::hasAuthError() const
{
	// Halt command was pushed by server ('Auth Username/Password was not provided by peer')
	if (text.contains(QRegularExpression("Auth[\\x20|\\t]+Username\\/Password[\\x20|\\t]+was[\\x20|\\t]+"
			"not[\\x20|\\t]+provided[\\x20|\\t]+by[\\x20|\\t]+peer",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// Auth username is empty
	if (text.contains(QRegularExpression("Auth[\\x20|\\t]+username[\\x20|\\t]+is[\\x20|\\t]+empty",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// AUTH: Received control message: AUTH_FAILED
	if (text.contains(QRegularExpression(
			"AUTH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:[\\x20|\\t]+AUTH_FAILED",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::hasNeedPEMpass() const
{
	// Need PEM pass phrase for private key
	return text.contains(QRegularExpression(
		"Need[\\x20|\\t]+PEM[\\x20|\\t]+pass[\\x20|\\t]+phrase[\\x20|\\t]+for[\\x20|\\t]+private[\\x20|\\t]+key",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasUnknownCA() const
{
	// tlsv1 alert unknown ca
	return text.contains(QRegularExpression("tlsv1[\\x20|\\t]+alert[\\x20|\\t]+unknown[\\x20|\\t]+ca",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasTLSError() const
{
	// SSL routines:... 错误消息太多了(看一下Ssl_err.c), 捕获通用消息TLS_ERROR: BIO (read|write)
/*
	// SSL routines:SSL23_GET_SERVER_HELLO:unsupported protocol
	if (text.contains(QRegularExpression("SSL23_GET_SERVER_HELLO:[\\x20|\\t]*unsupported[\\x20|\\t]+protocol",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure
	if (text.contains(QRegularExpression("alert[\\x20|\\t]+handshake[\\x20|\\t]+failure",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// TLS Error: TLS handshake failed
	if (text.contains(QRegularExpression("TLS[\\x20|\\t]+Error:[\\x20|\\t]+TLS[\\x20|\\t]+handshake[\\x20|\\t]+failed",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// ...
*/

	// TLS_ERROR: BIO read ...
	if (text.contains(QRegularExpression("TLS_ERROR:[\\x20|\\t]*BIO[\\x20|\\t]+(read|write)",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// SSL3_READ_BYTES:ssl handshake failure
	if (text.contains(QRegularExpression("ssl[\\x20|\\t]+handshake[\\x20|\\t]+failure",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::hasClientCertificateRevoked() const
{
	// alert certificate revoked
	return text.contains(QRegularExpression("alert[\\x20|\\t]+certificate[\\x20|\\t]+revoked",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasClientCertificateExpired() const
{
	// alert certificate expired
	return text.contains(QRegularExpression("alert[\\x20|\\t]+certificate[\\x20|\\t]+expired",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasClientCertificateIsNotYetValid() const
{
	// certificate is not yet valid
	return text.contains(QRegularExpression("certificate[\\x20|\\t]+is[\\x20|\\t]+not[\\x20|\\t]+yet[\\x20|\\t]+valid",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasCannotLoadCertificate() const
{
	// TLS read certs fail, from my cert store by %s
	if (text.contains(QRegularExpression(
			"TLS[\\x20|\\t]+read[\\x20|\\t]+certs[\\x20|\\t]+fail,[\\x20|\\t]+from[\\x20|\\t]+my[\\x20|\\t]+cert[\\x20|\\t]+store",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// TLS read certs fail, from encrypt device by %s
	if (text.contains(QRegularExpression(
			"TLS[\\x20|\\t]+read[\\x20|\\t]+certs[\\x20|\\t]+fail,[\\x20|\\t]+from[\\x20|\\t]+encrypt[\\x20|\\t]+device",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// Cannot load certificate file
	if (text.contains(QRegularExpression("Cannot[\\x20|\\t]+load[\\x20|\\t]+certificate[\\x20|\\t]+file",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::hasUnableGetIssuerCert() const
{
	// VERIFY ERROR: depth=0, error=unable to get local issuer certificate: C=CN, CN=vpn_server
	if (text.contains(QRegularExpression("unable[\\x20|\\t]+to[\\x20|\\t]+get[\\x20|\\t]+local[\\x20|\\t]+issuer[\\x20|\\t]+certificate",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// VERIFY ERROR: depth=?, error=unable to get issuer certificate
	if (text.contains(QRegularExpression("unable[\\x20|\\t]+to[\\x20|\\t]+get[\\x20|\\t]+issuer[\\x20|\\t]+certificate",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::hasProxyRequireAuthentication() const
{
	// Proxy requires authentication
	return text.contains(QRegularExpression("Proxy[\\x20|\\t]+requires[\\x20|\\t]+authentication",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasAllTAPUsed() const
{
	// All TAP-Windows adapters on this system are currently in use.
	return text.contains(QRegularExpression(
		"All[\\x20|\\t]+TAP-Windows[\\x20|\\t]+adapters[\\x20|\\t]+on[\\x20|\\t]+this[\\x20|\\t]+system[\\x20|\\t]+"
		"are[\\x20|\\t]+currently[\\x20|\\t]+in[\\x20|\\t]+use",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasNoTAP() const
{
	// There are no TAP-Windows adapters on this system
	return text.contains(QRegularExpression(
		"There[\\x20|\\t]+are[\\x20|\\t]+no[\\x20|\\t]+TAP-Windows[\\x20|\\t]+adapters[\\x20|\\t]+on[\\x20|\\t]+this[\\x20|\\t]+system",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasUnsupportedCipher() const
{
	// encrypt device init fail, cipher SM1-CBC require hardware support! (OpenSSL)
	if (text.contains(QRegularExpression(
			"cipher[\\x20|\\t]+[\\w|\\-]+[\\x20|\\t]+require[\\x20|\\t]+hardware[\\x20|\\t]+support",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// cipher algorithm 'SM4-CBC' not found
	if (text.contains(QRegularExpression(
			"cipher[\\x20|\\t]+algorithm[\\x20|\\t]+[\\w|'|\\-]+[\\x20|\\t]+not[\\x20|\\t]+found",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::hasUnsupportedAuth() const
{
	// encrypt device init fail, auth SM3 require hardware support! (OpenSSL)
	if (text.contains(QRegularExpression(
			"auth[\\x20|\\t]+[\\w|\\-]+[\\x20|\\t]+require[\\x20|\\t]+hardware[\\x20|\\t]+support",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// Message hash algorithm 'SM3' not found
	if (text.contains(QRegularExpression(
			"Message[\\x20|\\t]+hash[\\x20|\\t]+algorithm[\\x20|\\t]+[\\w|'|\\-]+[\\x20|\\t]+not[\\x20|\\t]+found",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::hasDecryptError() const
{
	// EVP_DecryptFinal:bad decrypt
	return text.contains(QRegularExpression("EVP_DecryptFinal:[\\x20|\\t]*bad[\\x20|\\t]+decrypt",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasCannotResolveHostAddress() const
{
	// RESOLVE: Cannot resolve host address:
	return text.contains(QRegularExpression("RESOLVE:[\\x20|\\t]+Cannot[\\x20|\\t]+resolve[\\x20|\\t]+host[\\x20|\\t]+address",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasMacVerifyFailure() const
{
	// PKCS12_parse:mac verify failure
	return text.contains(QRegularExpression("PKCS12_parse:[\\x20|\\t]*mac[\\x20|\\t]+verify[\\x20|\\t]+failure",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasParameterError() const
{
	// Use --help for more information.
	return text.contains(QRegularExpression("Use[\\x20|\\t]+--help[\\x20|\\t]+for[\\x20|\\t]+more[\\x20|\\t]+information",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasConnectionError() const
{
	// TCP: connect to [AF_INET]10.5.12.11:1080 failed, will try again in 5 seconds: Connection timed out (WSAETIMEDOUT)
	// failed, will try again in 5 seconds: 系统试图将驱动器合并到合并驱动器上的目录。
	// recv_line: TCP port read failed on recv()
	return text.contains(QRegularExpression(
		"failed,[\\x20|\\t]+will[\\x20|\\t]+try[\\x20|\\t]+again[\\x20|\\t]+in[\\x20|\\t]+[0-9]+[\\x20|\\t]+seconds",
		QRegularExpression::CaseInsensitiveOption))
		|| text.contains(QRegularExpression(
			"TCP[\\x20|\\t]+port[\\x20|\\t]+read[\\x20|\\t]+failed[\\x20|\\t]+on[\\x20|\\t]+recv",
			QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasSigTermReceived() const
{
	// SIGTERM[hard,] received, process exiting
	// SIGTERM[soft,connection-reset] received, process exiting
	return text.contains(QRegularExpression("SIGTERM\\[[^\\]]*\\][\\x20|\\t]+received,[\\x20|\\t]+process[\\x20|\\t]+exiting",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::hasFatalError() const
{
	// Exiting due to fatal error
	return text.contains(QRegularExpression("Exiting[\\x20|\\t]+due[\\x20|\\t]+to[\\x20|\\t]+fatal[\\x20|\\t]+error",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestTrustServerCertificate() const
{
	// Trust server certificate[trust|reject]:
	return text.contains(QRegularExpression("Trust[\\x20|\\t]+server[\\x20|\\t]+certificate\\[trust\\|reject\\]:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestClientCertificate() const
{
	// Enter Client certificate:
	return text.contains(QRegularExpression("Enter[\\x20|\\t]+Client[\\x20|\\t]+certificate:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestPrivateKeyPassword() const
{
	// Enter Private Key Password:
	if (text.contains(QRegularExpression("Enter[\\x20|\\t]+Private[\\x20|\\t]+Key[\\x20|\\t]+Password:",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// Enter Challenge Password:
	if (text.contains(QRegularExpression("Enter[\\x20|\\t]+Challenge[\\x20|\\t]+Password:",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// CHALLENGE: Please enter token PIN
	if (text.contains(QRegularExpression("CHALLENGE:[\\x20|\\t]+Please[\\x20|\\t]+enter[\\x20|\\t]+token[\\x20|\\t]+PIN",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::requestPrivateKeyEncrypt() const
{
	// Enter RSA sign: E946G4TZ6tA3X5iRfyYce5pvYQLBYDkPklotZ7Gntlrdixde
	// Enter PK sign: vLARpKX9Y5zGpH8NbUiG/KKbItoCwKSq/QNDB8gh4tWQOyq3
	return text.contains(QRegularExpression("Enter[\\x20|\\t]+(RSA|PK)[\\x20|\\t]+sign:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestUsername() const
{
	// Enter Auth Username:
	if (text.contains(QRegularExpression("Enter[\\x20|\\t]+Auth[\\x20|\\t]+Username:",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	// Enter Challenge Username:
	if (text.contains(QRegularExpression("Enter[\\x20|\\t]+Challenge[\\x20|\\t]+Username:",
			QRegularExpression::CaseInsensitiveOption)))
		return true;

	return false;
}

bool VPNLogParser::requestPassword() const
{
	// Enter Auth Password:
	return text.contains(QRegularExpression("Enter[\\x20|\\t]+Auth[\\x20|\\t]+Password:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestProxyUsername() const
{
	// Enter\\s+(HTTP|SOCKS)\\s+Proxy\\s+Username:
	return text.contains(QRegularExpression("Enter[\\x20|\\t]+(HTTP|SOCKS)[\\x20|\\t]+Proxy[\\x20|\\t]+Username:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestProxyPassword() const
{
	// Enter\\s+(HTTP|SOCKS)\\s+Proxy\\s+Password:
	return text.contains(QRegularExpression("Enter[\\x20|\\t]+(HTTP|SOCKS)[\\x20|\\t]+Proxy[\\x20|\\t]+Password:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestPolicyResponse() const
{
	// Evaluate policy[accept|reject]:
	return text.contains(QRegularExpression("Evaluate[\\x20|\\t]+policy\\[accept\\|reject\\]:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestOpenEncryptDevices() const
{
	// Encrypt device type load success lib_path=xxxx, device_type=xxxx
	return text.contains(QRegularExpression("Encrypt[\\x20|\\t]+device[\\x20|\\t]+type[\\x20|\\t]+load[\\x20|\\t]+success",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestResolveHost() const
{
	// RESOLVE_REMOTE: %s
	return text.contains(QRegularExpression("RESOLVE_REMOTE:[\\x20|\\t]+"));
}

bool VPNLogParser::requestConnectServer() const
{
	// TLS: Initial Handshake, sid=%s"
	// Attempting to establish TCP connection with %s
	return text.contains(QRegularExpression("TLS:[\\x20|\\t]+Initial[\\x20|\\t]+Handshake,",
		QRegularExpression::CaseInsensitiveOption)) ||
		text.contains(QRegularExpression("Attempting[\\x20|\\t]+to[\\x20|\\t]+establish[\\x20|\\t]+TCP[\\x20|\\t]+connection",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestClientConfig() const
{
	// SENT CONTROL [my_vpn_server]: 'PUSH_REQUEST' (status=1)
	return text.contains(QRegularExpression("SENT[\\x20|\\t]+CONTROL[\\x20|\\t]+.+PUSH_REQUEST",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestAssignIPAddress() const
{
	// TAP-WIN32 device [46] [本地连接 12] opened: \\.\Global\{407A7234-DAC1-4F52-B5A3-33C22DF51088}.tap
	return text.contains(QRegularExpression("TAP-WIN32[\\x20|\\t]+device[\\x20|\\t]+.+opened:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::requestAddRoutes() const
{
	// ADD_ROUTES
	return text.contains(QRegularExpression("ADD_ROUTES"));
}

bool VPNLogParser::isOpenEncryptDevices() const
{
	// open encrypt device:
	return text.contains(QRegularExpression("open[\\x20|\\t]+encrypt[\\x20|\\t]+device:",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isPolicy() const
{
	// POLICY: password https://10.5.0.227/chg_passwd.do weak_password
	return text.contains(QRegularExpression("POLICY:[\\x20|\\t]+.+$", QRegularExpression::MultilineOption));
}

bool VPNLogParser::isTLSDetails() const
{
	// Control Channel: GMTLSv1.1, cipher TLSv1/SSLv3 ECDHE-SM4-SM3
	return text.contains(QRegularExpression("Control[\\x20|\\t]+Channel:[\\x20|\\t]+",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isCipher() const
{
	// Data Channel Encrypt: Cipher 'SM1-CBC' initialized with 128 bit key
	return text.contains(QRegularExpression("Data[\\x20|\\t]+Channel[\\x20|\\t]+Encrypt:[\\x20|\\t]+Cipher[\\x20|\\t]+",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isAuth() const
{
	// Data Channel Encrypt: Using 160 bit message hash 'SHA1' for HMAC authentication
	return text.contains(QRegularExpression("Data[\\x20|\\t]+Channel[\\x20|\\t]+Encrypt:[\\x20|\\t]+Using[\\x20|\\t]+",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isFragmentOption() const
{
	// Data Channel Fragment: '1300'
	return text.contains(QRegularExpression("Data[\\x20|\\t]+Channel[\\x20|\\t]+Fragment:[\\x20|\\t]+'",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isCompressionOption() const
{
	// Data Channel Compress: 'adaptive'
	return text.contains(QRegularExpression("Data[\\x20|\\t]+Channel[\\x20|\\t]+Compress:[\\x20|\\t]+'",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isTunDeviceType() const
{
	// TUN/TAP device type: 'tap'
	return text.contains(QRegularExpression("TUN/TAP[\\x20|\\t]+device[\\x20|\\t]+type:[\\x20|\\t]+'",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isTunDeviceName() const
{
#ifdef _WIN32
	// TAP-WIN32 device [12] [本地连接 12] opened: \\.\Global\{72651266-8FE5-4488-88C7-AB1877BD162D}.tap
	return text.contains(QRegularExpression("TAP-WIN32[\\x20|\\t]+device[\\x20|\\t]+\\[",
		QRegularExpression::CaseInsensitiveOption));
#else
	// TUN/TAP device tun0 opened
	return text.contains(QRegularExpression("TUN/TAP[\\x20|\\t]+device[\\x20|\\t]+([^\\x20\\t]+)[\\x20|\\t]+opened",
		QRegularExpression::CaseInsensitiveOption));
#endif
}

#ifdef _WIN32
bool VPNLogParser::isTunDeviceIndex() const
{
	// TAP-WIN32 device [12] [本地连接 12] opened: \\.\Global\{72651266-8FE5-4488-88C7-AB1877BD162D}.tap
	return text.contains(QRegularExpression("TAP-WIN32[\\x20|\\t]+device[\\x20|\\t]+\\[",
		QRegularExpression::CaseInsensitiveOption));
}
#endif

bool VPNLogParser::isVirtualIPv4Gateway() const
{
	// PUSH: Received control message: 'PUSH_REPLY,echo,route-gateway 172.16.111.1,ping 10,ping-restart 120,...
	return text.contains(QRegularExpression("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*route-gateway[\\x20|\\t]+[^,|'|\\n]+",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isVirtualIPv4Addr() const
{
	// PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.16.111.1,ifconfig 172.16.111.2 255.255.255.0...
	return text.contains(QRegularExpression("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ifconfig[\\x20|\\t]+[^\\x20|\\t]+[\\x20|\\t]+[^,|'|\\n]+",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isVirtualIPv6Addr() const
{
	// PUSH: Received control message: 'PUSH_REPLY,ifconfig-ipv6 2001:da2:200:20::1000/64 2001:da2:200:20::1,ifconfig 192.168.103.6 255.255.255.0,...
	return text.contains(QRegularExpression("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ifconfig-ipv6[\\x20|\\t]+[^\\x20|\\t]+[\\x20|\\t]+[^,|'|\\n]+",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isKeepAlive() const
{
	// PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.16.111.1,topology subnet,ping 10,ping-restart 120,...'
	// PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.16.111.1,topology subnet,ping 10,ping-restart 120'
	return text.contains(QRegularExpression("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ping[\\x20|\\t]+[^,|'|\\n]+",
		QRegularExpression::CaseInsensitiveOption)) &&
		text.contains(QRegularExpression("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ping-restart[\\x20|\\t]+[^,|'|\\n]+",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isInitializationSequenceCompleted() const
{
	// Initialization Sequence Completed
	return text.contains(QRegularExpression("Initialization[\\x20|\\t]+Sequence[\\x20|\\t]+Completed",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::isRestarting() const
{
	// SIGUSR1[hard,] received, process restarting
	// SIGHUP[hard,] received, process restarting
	// SIGUSR1[soft,ping-restart] received, process restarting
	return text.contains(QRegularExpression("(SIGUSR1|SIGHUP).+,[\\x20|\\t]+process[\\x20|\\t]+restarting",
		QRegularExpression::CaseInsensitiveOption));
}

bool VPNLogParser::getUnsupportedCipher(QString& cipher)
{
	// encrypt device init fail, cipher SM1-CBC require hardware support! (OpenSSL)
	QRegularExpression regexp0("cipher[\\x20|\\t]+([\\w|\\-]+)[\\x20|\\t]+require[\\x20|\\t]+hardware[\\x20|\\t]+support",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match0 = regexp0.match(text);
	if (match0.hasMatch()) {
//		qDebug() << "group0:" << match0.captured(0) << "group1:" << match0.captured(1);
		cipher = match0.captured(1).trimmed();
		return true;
	}

	// cipher algorithm 'SM4-CBC' not found
	QRegularExpression regexp1("cipher[\\x20|\\t]+algorithm[\\x20|\\t|']+([^']+)['|\\x20|\\t]+not[\\x20|\\t]+found",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match1 = regexp1.match(text);
	if (match1.hasMatch()) {
//		qDebug() << "group0:" << match1.captured(0) << "group1:" << match1.captured(1);
		cipher = match1.captured(1).trimmed();
		return true;
	}

	return false;
}

bool VPNLogParser::getUnsupportedAuth(QString& auth)
{
	// encrypt device init fail, auth SM3 require hardware support! (OpenSSL)
	QRegularExpression regexp0("auth[\\x20|\\t]+([\\w|\\-]+)[\\x20|\\t]+require[\\x20|\\t]+hardware[\\x20|\\t]+support",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match0 = regexp0.match(text);
	if (match0.hasMatch()) {
//		qDebug() << "group0:" << match0.captured(0) << "group1:" << match0.captured(1);
		auth = match0.captured(1).trimmed();
		return true;
	}

	// Message hash algorithm 'SM3' not found
	QRegularExpression regexp1("Message[\\x20|\\t]+hash[\\x20|\\t]+algorithm[\\x20|\\t|']+([^']+)['|\\x20|\\t]+not[\\x20|\\t]+found",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match1 = regexp1.match(text);
	if (match1.hasMatch()) {
//		qDebug() << "group0:" << match1.captured(0) << "group1:" << match1.captured(1);
		auth = match1.captured(1).trimmed();
		return true;
	}

	return false;
}

bool VPNLogParser::getOpenedEncryptDevices(VPNTunnel& tunnel)
{
	// open encrypt device: 03034215
	// open encrypt device: HSIC USB Key 00 00
	QRegularExpression regexp("open[\\x20|\\t]+encrypt[\\x20|\\t]+device:(.+)$",
			QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);

	bool result = false;
	QStringList deviceList = tunnel.getOpenedEncryptDevices();

	QRegularExpressionMatchIterator it = regexp.globalMatch(text);
	while (it.hasNext()) {
		QRegularExpressionMatch match = it.next();
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		deviceList.append(match.captured(1).trimmed());
		result = true;
	}

	tunnel.setOpenedEncryptDevices(deviceList);
	return result;
}

bool VPNLogParser::getPolicys(QStringList& policys)
{
	bool result = false;

	// POLICY: password https://10.5.0.227/chg_passwd.do weak_password
	// 可以输出多个POLICY: 请求
	QRegularExpression regexp("POLICY:[\\x20|\\t]+(.+)$", QRegularExpression::MultilineOption);

	QRegularExpressionMatchIterator it = regexp.globalMatch(text);
	while (it.hasNext()) {
		QRegularExpressionMatch match = it.next();
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		const QString externalForm = match.captured(1).trimmed();
		if (!externalForm.isEmpty())
			policys.append(externalForm);
		result = true;
	}

	return result;
}

bool VPNLogParser::getTunDeviceType(VPNTunnel& tunnel)
{
	// TUN/TAP device type: 'tap'
	QRegularExpression regexp("TUN/TAP[\\x20|\\t]+device[\\x20|\\t]+type:[\\x20|\\t|']+([^']+)",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		QString deviceType = match.captured(1).trimmed();
		if (deviceType.compare("tap", Qt::CaseInsensitive) == 0)
			tunnel.setTunDeviceType(VPNTunnel::TAP);
		else
			tunnel.setTunDeviceType(VPNTunnel::TUN);
		return true;
	}

	return false;
}

bool VPNLogParser::getTunDeviceName(VPNTunnel& tunnel)
{
#ifdef _WIN32
	// TAP-WIN32 device [12] [本地连接 12] opened: \\.\Global\{72651266-8FE5-4488-88C7-AB1877BD162D}.tap
	QRegularExpression regexp("TAP-WIN32[\\x20|\\t]+device[\\x20|\\t]+[\\[]([0-9]+)[^\\[]+[\\[]([^\\]]+)",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1) << "group2:" << match.captured(2);
//		QString tunDeviceIndex = match.captured(1).trimmed();
		QString tunDeviceName = match.captured(2).trimmed();
		tunnel.setTunDeviceName(tunDeviceName);
		return true;
	}
#else
	// TUN/TAP device tun0 opened
	QRegularExpression regexp("TUN/TAP[\\x20|\\t]+device[\\x20|\\t]+([^\\x20\\t]+)[\\x20|\\t]+opened",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		QString tunDeviceName = match.captured(1).trimmed();
		tunnel.setTunDeviceName(tunDeviceName);
		return true;
	}
#endif

	return false;
}

#ifdef _WIN32
bool VPNLogParser::getTunDeviceIndex(VPNTunnel& tunnel)
{
	// TAP-WIN32 device [12] [本地连接 12] opened: \\.\Global\{72651266-8FE5-4488-88C7-AB1877BD162D}.tap
	QRegularExpression regexp("TAP-WIN32[\\x20|\\t]+device[\\x20|\\t]+[\\[]([0-9]+)[^\\[]+[\\[]([^\\]]+)",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1) << "group2:" << match.captured(2);
		QString tunDeviceIndex = match.captured(1).trimmed();
//		QString tunDeviceName = match.captured(2).trimmed();
		tunnel.setTunDeviceIndex(tunDeviceIndex.toULongLong());
		return true;
	}

	return false;
}
#endif

bool VPNLogParser::getVirtualIPv4Gateway(VPNTunnel& tunnel)
{
	// PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.16.111.1,ifconfig 172.16.111.2 255.255.255.0,...
	QRegularExpression regexp("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*route-gateway[\\x20|\\t]+([^,|'|\\n]+)",
		QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		tunnel.setVirtualIPv4Gateway(match.captured(1).trimmed());
		return true;
	}

	return false;
}

bool VPNLogParser::getVirtualIPv4Addr(VPNTunnel& tunnel)
{
	// PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.16.111.1,ifconfig 172.16.111.2 255.255.255.0,...
	QRegularExpression regexp("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ifconfig[\\x20|\\t]+([^\\x20|\\t]+)[\\x20|\\t]+([^,|'|\\n]+)",
		QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
		QString ipv4Addr = match.captured(1).trimmed();
		QString netmask = match.captured(2).trimmed();
		if (!netmask.isEmpty() && netmask.startsWith("255.", Qt::CaseInsensitive)) {
			const int bitsLen = count_netmask_bits(qPrintable(netmask));
			if (bitsLen > 0)
				ipv4Addr.append("/").append(QString::number(bitsLen));
		}
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1) << "group2:" << match.captured(2);
		tunnel.setVirtualIPv4Addr(ipv4Addr);
		return true;
	}

	return false;
}

bool VPNLogParser::getVirtualIPv6Addr(VPNTunnel& tunnel)
{
	// PUSH: Received control message: 'PUSH_REPLY,ifconfig-ipv6 2001:da2:200:20::1000/64 2001:da2:200:20::1,ifconfig 192.168.103.6 255.255.255.0,...
	QRegularExpression regexp("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ifconfig-ipv6[\\x20|\\t]+([^,|'|\\n]+)",
		QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		QStringList items = match.captured(1).trimmed().split(QRegularExpression("[\\x20|\\t]+"), QString::SkipEmptyParts);
		if (items.size() == 2) {
			tunnel.setVirtualIPv6Addr(items.at(0));
			tunnel.setVirtualIPv6Gateway(items.at(1));
			return true;
		}
	}

	return false;
}

bool VPNLogParser::getKeepAlive(VPNTunnel& tunnel)
{
	// PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.16.111.1,topology subnet,ping 10,ping-restart 120,...'
	// PUSH: Received control message: 'PUSH_REPLY,route-gateway 172.16.111.1,topology subnet,ping 10,ping-restart 120'
	QRegularExpression regexp0("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ping[\\x20|\\t]+([^,|'|\\n]+)",
		QRegularExpression::CaseInsensitiveOption);
	QRegularExpression regexp1("PUSH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:"
		".+,[\\x20|\\t]*ping-restart[\\x20|\\t]+([^,|'|\\n]+)",
		QRegularExpression::CaseInsensitiveOption);

	int ping = -1, restart = -1;

	QRegularExpressionMatch match0 = regexp0.match(text);
	if (match0.hasMatch()) {
		bool ok = false;
		ping = match0.captured(1).trimmed().toInt(&ok);
	}

	QRegularExpressionMatch match1 = regexp1.match(text);
	if (match1.hasMatch()) {
		bool ok = false;
		restart = match1.captured(1).trimmed().toInt(&ok);
	}

	if (ping > 0 && restart > 0) {
		tunnel.setKeepAlive(QPair<int, int>(ping, restart));
		return true;
	}
	return false;
}

bool VPNLogParser::getRestartingReason(QString& reason)
{
	// SIGUSR1[hard,] received, process restarting
	// SIGHUP[hard,] received, process restarting
	// SIGUSR1[soft,ping-restart] received, process restarting
	QRegularExpression regexp("(SIGUSR1|SIGHUP)\\[(hard|soft)[\\x20|\\t]*,([^,]*)\\]",
		QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
		//	qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1) << "group3:" << match.captured(3);
		reason.append(match.captured(1).trimmed());
		if (!match.captured(3).trimmed().isEmpty())
			reason.append(", ").append(match.captured(3).trimmed());
		return true;
	}

	return false;
}

bool VPNLogParser::getTLSVersion(VPNTunnel& tunnel)
{
	// Enter Client certificate:TLSv1
	QRegularExpression regexp0("Enter[\\x20|\\t]+Client[\\x20|\\t]+certificate:(.+)$",
			QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);

	QRegularExpressionMatch match0 = regexp0.match(text);
	if (match0.hasMatch()) {
//		qDebug() << "group0:" << match0.captured(0) << "group1:" << match0.captured(1);
		tunnel.setTLSVersion(match0.captured(1).trimmed());
		return true;
	}

	// Control Channel: TLSv1, cipher TLSv1/SSLv3 RC4-MD5, 1024 bit RSA
	QRegularExpression regexp1("Control[\\x20|\\t]+Channel:([^,]+)");
	QRegularExpressionMatch match1 = regexp1.match(text);
	if (match1.hasMatch()) {
//		qDebug() << "group0:" << match1.captured(0) << "group1:" << match1.captured(1);
		tunnel.setTLSVersion(match1.captured(1).trimmed());
		return true;
	}

	return false;
}

bool VPNLogParser::getTLSCipher(VPNTunnel& tunnel)
{
	// Control Channel: TLSv1, cipher TLSv1/SSLv3 RC4-MD5, 1024 bit RSA
	QRegularExpression regexp("Control[\\x20|\\t]+Channel:[\\x20|\\t]+[^,]+,([^,]+),",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		const QStringList items = match.captured(1).split(QRegularExpression("\\s"), QString::KeepEmptyParts);
		if (!items.isEmpty())
			tunnel.setTLSCipher(items.last());
		return true;
	}

	return false;
}

bool VPNLogParser::getCipher(VPNTunnel& tunnel)
{
	// Data Channel Encrypt: Cipher 'SM1-CBC' initialized with 128 bit key
	QRegularExpression regexp("Data[\\x20|\\t]+Channel[\\x20|\\t]+Encrypt:[\\x20|\\t]+Cipher[\\x20|\\t|']+([^']+)",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		tunnel.setCipher(match.captured(1).trimmed());
		return true;
	}

	return false;
}

bool VPNLogParser::getAuth(VPNTunnel& tunnel)
{
	// Data Channel Encrypt: Using 160 bit message hash 'SHA1' for HMAC authentication
	QRegularExpression regexp("Data[\\x20|\\t]+Channel[\\x20|\\t]+Encrypt:[\\x20|\\t]+Using[^']+[']([^']+)",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		tunnel.setAuth(match.captured(1).trimmed());
		return true;
	}

	return false;
}

bool VPNLogParser::getFragmentOption(VPNTunnel& tunnel)
{
	// Data Channel Fragment: '1300'
	QRegularExpression regexp("Data[\\x20|\\t]+Channel[\\x20|\\t]+Fragment:[\\x20|\\t|']+([^']+)",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		bool ok = false;
		int fragment = match.captured(1).trimmed().toInt(&ok);
		if (ok)
			tunnel.setFragment(fragment);
		return true;
	}

	return false;
}

bool VPNLogParser::getCompressionOption(VPNTunnel& tunnel)
{
	// Data Channel Compress: 'adaptive'
	QRegularExpression regexp("Data[\\x20|\\t]+Channel[\\x20|\\t]+Compress:[\\x20|\\t|']+([^']+)",
			QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		const QString option = match.captured(1).trimmed();
		if (option.compare("adaptive", Qt::CaseInsensitive) == 0)
			tunnel.setCompressionOption(VPNTunnel::ADAPTIVE);
		else if (option.compare("yes", Qt::CaseInsensitive) == 0)
			tunnel.setCompressionOption(VPNTunnel::YES);
		else
			tunnel.setCompressionOption(VPNTunnel::NO);
		return true;
	}

	return false;
}

bool VPNLogParser::getPrivateKeyEncryptReqeust(QString& encryptReqeust)
{
	/* 使用微软CertStore中的证书时, 无法支持TLSv1_3, TLSv1_2, 因为Cryptapi不支持任意长度签名, 详细看一下cryptoapi.c文件 */
#define ENCRYPT_REQUEST_LENGTH 48
#define SSL_SIG_LENGTH	36	/* Size of an SSL signature: MD5+SHA1 */

	// Enter RSA sign: E946G4TZ6tA3X5iRfyYce5pvYQLBYDkPklotZ7Gntlrdixde
	// Enter PK sign: SSji7+OOm6z0LT0U+G6FAMYwvsjdIKzxZjnMB69bpowspP22
	QRegularExpression regexp("Enter[\\x20|\\t]+(RSA|PK)[\\x20|\\t]+sign:(.+)$",
			QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1) << "group2:" << match.captured(2);
		encryptReqeust = match.captured(2).trimmed();
/*
		// 注解掉, 可能采用ECDSA签名
		if (encryptReqeust.size() > ENCRYPT_REQUEST_LENGTH)
			encryptReqeust = encryptReqeust.mid(0, ENCRYPT_REQUEST_LENGTH);
*/
		return true;
	}

	return false;
}

bool VPNLogParser::getAuthErrorReason(QString& errorReason)
{
	// AUTH: Received control message: AUTH_FAILED,client-reason 密码错误
	QRegularExpression regexp(
			"AUTH:[\\x20|\\t]+Received[\\x20|\\t]+control[\\x20|\\t]+message:[\\x20|\\t]+AUTH_FAILED,"
			"[\\x20|\\t]*(.+)$",
			QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		QStringList items = match.captured(1).split(QRegularExpression("[\\x20|\\t]"));
		if (!items.isEmpty()) {
			errorReason = items.last().trimmed();
			return true;
		}
	}

	return false;
}

bool VPNLogParser::getRetryCount(int *retryCount)
{
	// ERROR: Private Key Password verify fail, retry_count=8
	QRegularExpression regexp(
		"ERROR:[\\x20|\\t]+Private[\\x20|\\t]+Key[\\x20|\\t]+Password[\\x20|\\t]+verify[\\x20|\\t]+fail"
		",[\\x20|\\t]*retry_count[\\x20|\\t]*=[\\x20|\\t]*([\\d]+)",
		QRegularExpression::CaseInsensitiveOption);

	QRegularExpressionMatch match = regexp.match(text);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		QString number = match.captured(1).trimmed();
		bool ok = false;
		*retryCount = number.toInt(&ok);
		return true;
	}

	return false;
}

bool VPNLogParser::getCertificateChain(QStringList& certChain)
{
	// FIXME 引导和结尾-字符可以增减
	return extractContents(text, QLatin1String("-----BEGIN CERTIFICATE-----"), QLatin1String("-----END CERTIFICATE-----"),
		false, certChain);
}

bool VPNLogParser::getKeyTypes(QStringList& keyTypes)
{
	Q_UNUSED(keyTypes);
	return true;
}

bool VPNLogParser::getIssuers(QStringList& issuers)
{
	bool result = false;

	if (text.contains(QRegularExpression("Enter[\\x20|\\t]+Client[\\x20|\\t]+certificate:",
			QRegularExpression::CaseInsensitiveOption))) {

		QStringList items;
		// FIXME 引导和结尾-字符可以增减
		result = extractContents(text, QLatin1String("-----BEGIN CA DN-----"), QLatin1String("-----END CA DN-----"),
			true, items);
		if (result) {
			for (int i = 0; i < items.size(); ++i)
				issuers.append(items.at(i).split(QLatin1Char('\n'), QString::SkipEmptyParts));
		}
	}

	return result;
}

bool VPNLogParser::extractContents(const QString& text, const QString& beginDelim, const QString& endDelim,
		bool stripDelim, QStringList& contents)
{
//	qDebug() << "input:\n" << text << "\nbegin_delim:" << beginDelim << "\nend_delim:" << endDelim;
	QString temp, input = text;
	QStringList tempList;
	bool result = false;
	int i;

	while ((i = input.indexOf(beginDelim)) >= 0) {
		input = stripDelim ? input.right(input.size() - (i + beginDelim.size())) : input.right(input.size() - i);
		if ((i = input.indexOf(endDelim)) >= 0) {
			temp = stripDelim ? input.left(i).trimmed() : input.left(i + endDelim.size()).trimmed();
//			qDebug() << "content:\n" << temp << "\n";
			tempList.append(temp);
			input = input.right(input.size() - (i + endDelim.size()));
			result = true;
		} else {
			result = false;
			break;
		}
	}

	// result == true 表示有匹配的开始边界和结束边界; 有空白行表示内容结束
	if (result && input.indexOf(QRegularExpression("\\r*\\n\\r*\\n")) == 0) {
		contents = tempList;
		return true;
	} else {
		return false;
	}
}
