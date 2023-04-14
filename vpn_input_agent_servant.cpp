#include <QApplication>
#include <QDateTime>
#include <QFile>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

#ifdef ENABLE_GUOMI
#include <openssl/encrypt_device.h>
#endif

#include <stdio.h>
#include <ctype.h>

#include "common/common.h"
#include "common/message_box_util.h"
#include "common/passphrase_generator.h"
#include "common/vpn_config.h"
#include "common/cipher.h"
#include "common/x509_certificate_util.h"
#include "common/encrypt_device_manager.h"

#include "settings.h"
#include "trust_certificate.h"
#include "select_certificate.h"
#include "passphrase_dialog.h"
#include "user_pass_dialog.h"
#include "vpn_input_agent_servant.h"
#include "preferences.h"

static int trustedCAs_refcount = 0;
QList<X509*> VPNInputAgentServant::trustedCAs;

VPNInputAgentServant::VPNInputAgentServant(QWidget *_parent, VPNConfig *_config, const QString& _uniqueIdentify,
		const QString& _fingerprint)
	: QObject(_parent), VPNInputAgentSkeleton(_uniqueIdentify), inputCanceled(false), fingerprint(_fingerprint),
	config(_config)
{
	++trustedCAs_refcount;
}

VPNInputAgentServant::~VPNInputAgentServant()
{
	--trustedCAs_refcount;
	if (trustedCAs_refcount == 0) {
		X509CertificateUtil::free_all_cert(trustedCAs);
		trustedCAs.clear();
	}
}

bool VPNInputAgentServant::isCanceled(const Context& ctx)
{
	Q_UNUSED(ctx)

	return this->inputCanceled;
}

VPNInputAgentI::TrustOption VPNInputAgentServant::trustServerCertificate(const QStringList& x509Chain,
		const Context& ctx)
{
	Q_UNUSED(ctx)

	VPNInputAgentI::TrustOption option = VPNInputAgentI::None;
	this->inputCanceled = false;

	QList<X509*> x509_list;
	for (int i = 0; i < x509Chain.size(); ++i)
		x509_list.append(X509CertificateUtil::load_from_memory(x509Chain.at(i).toLocal8Bit()));

	// ͨ�������ж�֤�����Ƿ��ѱ�����(!!trustedCAs�ܶ�, ɨ������֤��ûʲô����Ӱ��)
	int trustedChain = 0;
	for (int j = 0; j < x509_list.size(); ++j) {
		if (X509CertificateUtil::contains(trustedCAs, x509_list.at(j)))
			++trustedChain;
		else
			break;
	}
	if (trustedChain == x509_list.size()) {
		X509CertificateUtil::free_all_cert(x509_list);
		return VPNInputAgentI::Trust;
	}

	if (x509_list.size() > 1) {
		Preferences *preferences = qobject_cast<Preferences*>(this->parent());
		// TrustCertificate����ʱ�ͷ�x509_list
		TrustCertificate dialog(preferences, TrustCertificate::tr("Security warning"), x509_list);
		if (QDialog::Accepted == dialog.exec()) {
			option = VPNInputAgentI::Trust;

			cacheTrustedCAs(x509_list);	// �������ε�֤����
			if (dialog.isPersist()) {
				x509_list.removeFirst();	// ɾ�������֤��
				X509CertificateUtil::add_cert_to_file(Settings::instance()->getCAFileName(), x509_list);
			}
		} else {
			this->inputCanceled = true;	// �û���������
			this->config->setAutoReconnect(false);
		}
	}

	return option;
}

X509CertificateInfo VPNInputAgentServant::chooseClientCertificate(const QString& tlsVersion, const QStringList& keyTypes,
		const QStringList& issuers, const Context& ctx)
{
	Q_UNUSED(ctx)

	QString title = SelectCertificate::tr("Choose client certificate");
	if (!tlsVersion.isEmpty())
		title.append(QLatin1String("  [")).append(tlsVersion).append(QLatin1String("]"));
	title.append(QLatin1String("  (")).append(config->getName()).append(QLatin1String(")"));

	Preferences *preferences = qobject_cast<Preferences*>(this->parent());
	SelectCertificate dialog(preferences, title, config->getX509UserNameField(), tlsVersion, keyTypes, issuers);
	this->inputCanceled = false;

	X509CertificateInfo cert_info = config->getCredentials().getCertificateInfo();
	bool reselect = cert_info.isEmpty();

	if (!reselect) {	// �л����֤����Ϣ, ����Ƿ���Ч
		if (!dialog.hasCertificateInfo(&cert_info))
			// �����豸û�в���, ��Ҫ����������ȫ��Ϣ, ���Ի���, �����û��Ժ��������豸
			reselect = true;
	}

	if (reselect) {
		if (dialog.exec() == QDialog::Accepted) {
			X509CertificateInfo *selected_cert_info = dialog.getCertificateInfo();
			if (selected_cert_info) {
				if (*selected_cert_info != cert_info)
					config->getCredentials().clear();	// �����ͻ�֤��, �������а�ȫ��Ϣ
				config->getCredentials().setCertificateInfo(*selected_cert_info);	// ����ѡ��Ŀͻ�֤��
			}
		} else {
			this->inputCanceled = true;	// �û���������
			this->config->setAutoReconnect(false);
		}
	}

	Q_ASSERT (this->inputCanceled || !config->getCredentials().getCertificateInfo().isEmpty());
	return config->getCredentials().getCertificateInfo();
}

QByteArray VPNInputAgentServant::getPrivateKeyPassword(const Context& ctx)
{
	Credentials &credentials = config->getCredentials();
	const X509CertificateInfo& certInfo = credentials.getCertificateInfo();

	this->inputCanceled = false;

	if (credentials.getKeyPassword().isEmpty()) {
		// �ܶ�USB-KEY��֧�ֶ��߳�, ��Ҫ��ǰ̨У��PIN
		if (QLatin1String(ENCRYPT_DEVICE_SOURCE) == certInfo.getSource()) {
			QString description = PassphraseDialog::tr("Application is requesting access to a Protected item");
			if (ctx.hasAttribute(Context::PIN_ERROR))
				description = "<html><head/><body><p><span style='font-weight:600; color:#ff0000;'>"
					+ ctx.getAttribute(Context::PIN_ERROR).toString() + "</span></p></body></html>";
			Preferences *preferences = qobject_cast<Preferences*>(this->parent());
			PassphraseDialog dialog(preferences, PassphraseDialog::tr("Passphrase"), description, certInfo.getIdentity());
			if (QDialog::Accepted == dialog.exec())
				this->config->getCredentials().setKeyPassword(dialog.getPassphrase().toLocal8Bit());	// ����˽Կ��������
			else {
				this->inputCanceled = true;	// �û���������
				this->config->setAutoReconnect(false);
			}

		} else if (QLatin1String(MS_CRYPTAPI_SOURCE) == certInfo.getSource()) {
			Q_ASSERT(0); //������

		} else {
			Q_ASSERT(!certInfo.getSource().isEmpty());	// ֤������PKCS12�ļ�
			const QByteArray secretKey = PassphraseGenerator::generatePKCS12Passphrase();
			credentials.setKeyPassword(secretKey);
		}
	}

	Q_ASSERT (this->inputCanceled || !config->getCredentials().getKeyPassword().isEmpty());
	return config->getCredentials().getKeyPassword();
}

QByteArray VPNInputAgentServant::getPrivateKeyEncrypt(const QString& plaintext, const Context& ctx)
{
	Q_UNUSED(ctx)

	const X509CertificateInfo& certInfo = config->getCredentials().getCertificateInfo();
	if (certInfo.isEmpty()) {
		qDebug() << "X509CertificateInfo is empty";
		this->inputCanceled = true;
		this->config->setAutoReconnect(false);
		return QByteArray();
	}

	QByteArray digest = QByteArray::fromBase64(plaintext.toLocal8Bit());
	if (certInfo.getSource().compare(QLatin1String(MS_CRYPTAPI_SOURCE), Qt::CaseInsensitive) == 0) {
		return getMSPrivateKeyEncrypt(digest, certInfo);
	} else {
#ifdef ENABLE_GUOMI
		return getGMPrivateKeyEncrypt(digest, certInfo);
#else
		qDebug() << certInfo.getSource() << "source don't support";
		return QByteArray();
#endif
	}
}

QByteArray VPNInputAgentServant::getMSPrivateKeyEncrypt(const QByteArray& digest, const X509CertificateInfo& certInfo)
{
	QByteArray sign_bytes;

#ifdef _WIN32
	/* ʹ��΢��CertStore�е�֤��ʱ, �޷�֧��TLSv1_3, TLSv1_2, ��ΪCryptapi��֧�����ⳤ��ǩ��, ��ϸ��һ��cryptoapi.c�ļ� */
#define SSL_SIG_LENGTH	36	/* Size of an SSL signature: MD5 + SHA1 */
	HCERTSTORE hStoreHandle = NULL;
	HCRYPTPROV crypt_prov = NULL;
	HCRYPTHASH hash = NULL;
	DWORD key_spec, hash_size, sig_len;
	BOOL free_crypt_prov = TRUE;

	unsigned char data_buf[1024], sign_buf[1024];

	this->inputCanceled = false;

	if (digest.size() != SSL_SIG_LENGTH) {
		qDebug() << "invalid message length " << QString::number(digest.size()) << "\n";
		goto finish;
	}

	memcpy (data_buf, digest.data(), digest.size());

	if ((hStoreHandle = CertOpenStore((LPCSTR) CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER |
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"MY"))) {
		PCCERT_CONTEXT cert_context = NULL;
		BIO *bio = NULL;
		X509 *cert = NULL;

		while (cert_context = CertEnumCertificatesInStore(hStoreHandle, cert_context)) {
			if (CryptAcquireCertificatePrivateKey(cert_context, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL,
					&crypt_prov, &key_spec, &free_crypt_prov)) {
				bio = BIO_new_mem_buf(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
				if (bio) {
					if ((cert = d2i_X509_bio(bio, NULL))) {
						if (X509_cmp(cert, certInfo.getCertificate()) == 0) {
							// !! Microsoft CSPs do not support the PP_CLIENT_HWND or PP_KEYSET_SEC_DESCR flags.
							// !! ע�������Ĵ���, ���PIN����, ����Windows�汾, Microsoft CSPs����ʾ�������, Ҫ����������
/*
							Preferences *preferences = qobject_cast<Preferences*>(this->parent());
							if (!CryptSetProvParam(crypt_prov, PP_CLIENT_HWND, (const BYTE*) preferences->winId(), 0))
								qDebug() << "CryptSetProvParam() fail!\n";
*/
							break;	// �ҵ�֤���Ӧ��˽Կ
						}
					}
					BIO_free(bio);
					bio = NULL;
				}
				if (free_crypt_prov)
					CryptReleaseContext(crypt_prov, 0);
			}
		}

		if (bio)
			BIO_free(bio);
		if (cert_context)
			CertFreeCertificateContext(cert_context);
		CertCloseStore(hStoreHandle, 0);
	}

	if (!crypt_prov) {	// û���ҵ�֤���Ӧ��˽Կ
		qDebug() << "find private key fail!\n";
		goto finish;
	}

	if (!CryptCreateHash(crypt_prov, CALG_SSL3_SHAMD5, 0, 0, &hash)) {
		qDebug() << "CryptCreateHash() fail " << GetLastError() << "\n";
		goto finish;
	}

	DWORD len = sizeof (hash_size);
	if (!CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *) &hash_size, &len, 0)) {
		qDebug() << "CryptGetHashParam() fail " << GetLastError() << "\n";
		goto finish;
	}
	if ((int) hash_size != SSL_SIG_LENGTH) {
		qDebug() << "invalid message length " << QString::number(digest.size()) << "\n";
		goto finish;
	}

	if (!CryptSetHashParam(hash, HP_HASHVAL, (BYTE *) data_buf, 0)) {
		qDebug() << "CryptSetHashParam() fail " << GetLastError() << "\n";
		goto finish;
	}

	sig_len = sizeof (data_buf);
	if (CryptSignHash(hash, key_spec, NULL, 0, data_buf, &sig_len)) {
		/* and now, we have to reverse the byte-order in the result from CryptSignHash()... */
		for (DWORD i = 0; i < sig_len; i++)
			sign_buf[i] = data_buf[sig_len - i - 1];
		sign_bytes.append((char*) sign_buf, sig_len);
	}

finish:
	if (sign_bytes.isEmpty()) {
		this->inputCanceled = true;	// !!��ȡǩ��ʧ��, Microsoft CSPs���ô���, ģ���û�ѡ�����
		this->config->setAutoReconnect(false);
	}

	if (hash)
		CryptDestroyHash(hash);
	if (free_crypt_prov)
		CryptReleaseContext(crypt_prov, 0);
#endif

	Q_ASSERT (this->inputCanceled || !sign_bytes.isEmpty());
	return sign_bytes;
}

#ifdef ENABLE_GUOMI
QByteArray VPNInputAgentServant::getGMPrivateKeyEncrypt(const QByteArray& digest, const X509CertificateInfo& certInfo)
{
	QString providerName = EncryptDeviceManager::instance()->getProviderName();
	QString pathName = certInfo.getIdentity();
	QString pin;
	QByteArray sign_bytes;
	int num = 0, retryCount = 20;

	// ���������������
	// !! �ܶ�USB-KEY��֧�ֶ��߳�, ��Ҫ��ǰ̨У��PIN

	QString description = PassphraseDialog::tr("Application is requesting access to a Protected item");
	Preferences *preferences = qobject_cast<Preferences*>(this->parent());
	PassphraseDialog dialog(preferences, PassphraseDialog::tr("Passphrase"), description, certInfo.getIdentity());

	while (num++ < MAX_AUTH_PASSWD_NUM) {
		if (QDialog::Accepted == dialog.exec()) {
			if (EncryptDeviceManager::instance()->verifyDevicePIN(providerName, pathName, dialog.getPassphrase(), &retryCount)) {
				pin = dialog.getPassphrase();
				break;
			} else {
				description = "<html><head/><body><p><span style='font-weight:600; color:#ff0000;'>"
					+ QApplication::translate("VPNAgentI", "Private Key Password verify fail") + ", ";
				if (retryCount <= 0)
					description += QApplication::translate("VPNAgentI", "Encrypt device locked");
				else
					description += QApplication::translate("VPNAgentI", "residual try count")  + " "
						+ QString::number(retryCount);
				description += "</span></p></body></html>";
				dialog.setDescription(description);
				dialog.clearPassphrase();
			}

		} else {
			this->inputCanceled = true;	// �û���������
			this->config->setAutoReconnect(false);
			break;
		}
	}

	if (pin.isEmpty()) {
		this->inputCanceled = true;	// PINУ�����, ��������
		this->config->setAutoReconnect(false);
	} else {
		sign_bytes = EncryptDeviceManager::instance()->sign(providerName, pathName, pin, digest);
		this->config->getCredentials().setKeyPassword(pin.toLocal8Bit());	// ����˽Կ��������
	}

	return sign_bytes;
}
#endif

QString VPNInputAgentServant::getUserName(const Context& ctx)
{
	this->inputCanceled = false;

#if defined(SELF_LOOP_REPLAY_TEST) && defined(_DEBUG)
	static qint64 lastConnectSequence = 0;	// ��һ���������

	// ���Ҳ���ʱ��������û���������
	if (ctx.hasAttribute(Context::VPN_CONNECT_SEQUENCE)) {
		const qint64 currConnectSequence = ctx.getAttribute(Context::VPN_CONNECT_SEQUENCE).value<qint64>();
		if (currConnectSequence > lastConnectSequence) {
			lastConnectSequence = currConnectSequence;
			config->getCredentials().setUserName(
				PassphraseGenerator::generatePassphrase(5 + rand() % 5, rand() % 7, "13").toBase64());
			config->getCredentials().setPassword(
				PassphraseGenerator::generatePassphrase(5 + rand() % 5, rand() % 3, "64").toBase64());
			return config->getCredentials().getUserName();
		}
	}
#endif

	if (config->getAuthOptions() & VPNConfig::DisablePassword) {	// ������֤��Ч, ��������, ��Ч�Զ�����
		Q_ASSERT(false);	// !!��Ӧ�����е�����
		this->inputCanceled = true;
		this->config->setAutoReconnect(false);

	} else if (config->getCredentials().getUserName().isEmpty()
#ifdef STRONG_SECURITY_RESTRICTION
		|| config->getCredentials().getPassword().isEmpty()
#endif
		|| ctx.hasAttribute(Context::AUTH_ERROR)) {
		QString description = UserPassDialog::tr("Please enter username and password");
		if (ctx.hasAttribute(Context::AUTH_ERROR))
			description = "<html><head/><body><p><span style='font-weight:600; color:#ff0000;'>"
				+ ctx.getAttribute(Context::AUTH_ERROR).toString() + "</span></p></body></html>";

		Preferences *preferences = qobject_cast<Preferences*>(this->parent());
		UserPassDialog dialog(preferences, UserPassDialog::tr("Enter Username and password"),
			description, config->getCredentials().getUserName());
		if (QDialog::Accepted == dialog.exec()) {
			QString password = dialog.getPassword();
			config->getCredentials().setUserName(dialog.getUserName());	// �����û�������
			config->getCredentials().setPassword(password);
		} else {
			this->inputCanceled = true;	// �û���������
			this->config->setAutoReconnect(false);
		}
	}

	Q_ASSERT (this->inputCanceled || !config->getCredentials().getUserName().isEmpty());
	return config->getCredentials().getUserName();
}

QString VPNInputAgentServant::getPassword(const Context& ctx)
{
	Q_UNUSED(ctx)

	// �Ѿ����û���һ������
	return config->getCredentials().getPassword();
}

QString VPNInputAgentServant::getOtp(const Context& ctx)
{
	Q_UNUSED(ctx)

	// �Ѿ����û���һ������
	return config->getCredentials().getOtp();
}

QString VPNInputAgentServant::getProxyUserName(const Context& ctx)
{
	this->inputCanceled = false;

	if (config->getCredentials().getProxyUserName().isEmpty()
#ifdef STRONG_SECURITY_RESTRICTION
		|| config->getCredentials().getProxyPassword().isEmpty()
#endif
		|| ctx.hasAttribute(Context::PROXY_AUTH_ERROR)) {
		QString description = UserPassDialog::tr("Please enter Proxy username and password");
		if (ctx.hasAttribute(Context::PROXY_AUTH_ERROR))
			description = "<html><head/><body><p><span style='font-weight:600; color:#ff0000;'>"
				+ ctx.getAttribute(Context::PROXY_AUTH_ERROR).toString() + "</span></p></body></html>";

		Preferences *preferences = qobject_cast<Preferences*>(this->parent());
		UserPassDialog dialog(preferences, UserPassDialog::tr("Enter Proxy Username and password"),
			description, config->getCredentials().getProxyUserName());
		if (QDialog::Accepted == dialog.exec()) {
			config->getCredentials().setProxyUserName(dialog.getUserName());	// ���ش����û�������
			config->getCredentials().setProxyPassword(dialog.getPassword());
		} else {
			this->inputCanceled = true;	// �û���������
			this->config->setAutoReconnect(false);
		}
	}

	Q_ASSERT (this->inputCanceled || !config->getCredentials().getProxyUserName().isEmpty());
	return config->getCredentials().getProxyUserName();
}

QString VPNInputAgentServant::getProxyPassword(const Context& ctx)
{
	Q_UNUSED(ctx)

	// �Ѿ��ʹ����û���һ������
	return config->getCredentials().getProxyPassword();
}

void VPNInputAgentServant::cacheTrustedCAs(const QList<X509*>& x509_list)
{
	X509 *x509_cert;
	QListIterator<X509*> it(x509_list);

	while (it.hasNext()) {
		x509_cert = it.next();
		if (!X509CertificateUtil::contains(trustedCAs, x509_cert)) {
			x509_cert = X509_dup(x509_cert);
			if (x509_cert)
				trustedCAs.append(x509_cert);
		}
	}

	while (trustedCAs.size() > MAX_TRUSTED_CA_CACHE) {
		x509_cert = trustedCAs.first();
		trustedCAs.removeFirst();
		if (x509_cert)
			X509_free(x509_cert);
	}
}
