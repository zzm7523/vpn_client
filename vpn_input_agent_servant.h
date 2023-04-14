#ifndef __VPN_INPUT_AGENT_SERVANT_H__
#define __VPN_INPUT_AGENT_SERVANT_H__

#include "config/config.h"

#include <QWidget>
#include <QString>
#include <QDialog>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "common/vpn_config.h"
#include "common/vpn_i_proxy.h"
#include "common/vpn_i_skeleton.h"

class VPNInputAgentServant: public QObject, public VPNInputAgentSkeleton
{
	Q_OBJECT
public:
	VPNInputAgentServant(QWidget *parent, VPNConfig *config, const QString& uniqueIdentify, const QString& fingerprint);
	~VPNInputAgentServant();

	virtual VPNInputAgentI::TrustOption trustServerCertificate(const QStringList& x509Chain, const Context& ctx);
	virtual X509CertificateInfo chooseClientCertificate(const QString& tlsVersion, const QStringList& keyTypes,
		const QStringList& issuers, const Context& ctx);

	virtual QByteArray getPrivateKeyPassword(const Context& ctx);
	virtual QByteArray getPrivateKeyEncrypt(const QString& plaintext, const Context& ctx);

	virtual QString getUserName(const Context& ctx);
	virtual QString getPassword(const Context& ctx);
	virtual QString getOtp(const Context& ctx);

	virtual QString getProxyUserName(const Context& ctx);
	virtual QString getProxyPassword(const Context& ctx);

	virtual bool isCanceled(const Context& ctx);

private:
	void cacheTrustedCAs(const QList<X509*>& x509_list);
	QByteArray getMSPrivateKeyEncrypt(const QByteArray& digest, const X509CertificateInfo& certInfo);
#ifdef ENABLE_GUOMI
	QByteArray getGMPrivateKeyEncrypt(const QByteArray& digest, const X509CertificateInfo& certInfo);
#endif

	bool inputCanceled;
	QString fingerprint;
	VPNConfig *config;

	static QList<X509*> trustedCAs;

};

#endif
