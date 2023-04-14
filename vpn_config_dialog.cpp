#include <QRegularExpression>
#include <QShowEvent>
#include <QFile>
#include <QTextStream>
#include <QFileDialog>

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/message_box_util.h"
#include "common/vpn_config.h"

#include "vpn_config_dialog.h"
#include "ui_vpn_config_dialog.h"
#include "settings.h"

VPNConfigDialog::VPNConfigDialog(QWidget *_parent, const QString& _windowTitle, VPNConfig *_config,
		VPNConfigManagerProxy *_configMgrProxy)
	: QDialog(_parent), m_ui(new Ui::VPNConfigDialog), configMgrProxy(_configMgrProxy)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(_windowTitle);

	m_ui->txtName->setFocus(Qt::ActiveWindowFocusReason);
	m_ui->txtHost->setValidator(new QRegExpValidator(QRegExp(QLatin1String("[a-z|A-Z|0-9|:|\\.|\\_|\\-]{1,64}")), this));
	m_ui->txtPort->setText(QString::number(VPN_PORT));
	m_ui->txtPort->setValidator(new QRegExpValidator(QRegExp(QLatin1String("[1-9][0-9]{1,4}")), this));
	m_ui->comboProtocol->clear();
	m_ui->comboProtocol->addItem(ServerEndpoint::protocol2String(ServerEndpoint::Udp));
	m_ui->comboProtocol->addItem(ServerEndpoint::protocol2String(ServerEndpoint::Tcp));
	m_ui->comboProtocol->addItem(ServerEndpoint::protocol2String(ServerEndpoint::Udp6));
	m_ui->comboProtocol->addItem(ServerEndpoint::protocol2String(ServerEndpoint::Tcp6));

	m_ui->controlSecurityOption->setVisible(false);
	m_ui->dataSecurityOption->setVisible(false);
	m_ui->proxySettingsOption->setVisible(false);

	m_ui->txtProxyHost->setValidator(new QRegExpValidator(QRegExp(QLatin1String("[a-z|A-Z|0-9|:|\\.|\\_|\\-]{1,64}")), this));
	m_ui->txtProxyPort->setValidator(new QRegExpValidator(QRegExp(QLatin1String("[1-9][0-9]{1,4}")), this));

	m_ui->btnAdvanced->setChecked(false);
	m_ui->btnAdvanced->setIcon(QIcon(QStringLiteral(":/images/adv_expand.png")));

	m_ui->comboPassAuth->clear();
	m_ui->comboPassAuth->addItem(tr("Auto probe"), static_cast<quint32>(VPNConfig::AutoProbe));
	m_ui->comboPassAuth->addItem(tr("Enable"), static_cast<quint32>(VPNConfig::EnablePassword));
	m_ui->comboPassAuth->addItem(tr("Disable"), static_cast<quint32>(VPNConfig::DisablePassword));
	// OpenVPN服务端一般都会启用密码认证(考虑到官方版OpenVPN不支持自动探测), 缺省要求密码认证
	int index = m_ui->comboPassAuth->findData(static_cast<quint32>(VPNConfig::EnablePassword));
	m_ui->comboPassAuth->setCurrentIndex(index > 0 ? index : 0);

	QStringList tlsVersionList;
	tlsVersionList.append(tr("Auto negotiate"));
	tlsVersionList.append(QString(QLatin1String(TLS_VERSION_LIST)).split(QLatin1Char(':')));
	m_ui->comboTlsVersion->clear();
	m_ui->comboTlsVersion->addItems(tlsVersionList);

	QStringList cipherList;
	cipherList.append(tr("Auto negotiate"));
#ifdef ENABLE_GUOMI
	cipherList.append(QString(QLatin1String(CHANNEL_HARDWARE_CIPHER_LIST)).split(QLatin1Char(':')));
#endif
	cipherList.append(QString(QLatin1String(CHANNEL_SOFTWARE_CIPHER_LIST)).split(QLatin1Char(':')));
	m_ui->comboCipher->clear();
	m_ui->comboCipher->addItems(cipherList);

	QStringList authList;
	authList.append(tr("Auto negotiate"));
	authList.append(QString(QLatin1String(CHANNEL_AUTH_LIST)).split(QLatin1Char(':')));
	m_ui->comboAuth->clear();
	m_ui->comboAuth->addItems(authList);

	// TLS Auth不能自动协商, 必须明确指定, 缺省SHA1
	m_ui->comboTlsAuth->addItems(QString(QLatin1String(CHANNEL_AUTH_LIST)).split(QLatin1Char(':')));
	index = m_ui->comboTlsAuth->findText(QLatin1String("SHA1"), Qt::MatchFixedString);
	m_ui->comboTlsAuth->setCurrentIndex(index > 0 ? index : 0);
	// Normally, the fllowing convention is used:
	// KEY_DIRECTION_NORMAL from server to client, KEY_DIRECTION_INVERSE from client to server
	m_ui->rbInverse->setChecked(true);

	setVPNConfig(_config);

	checkVPNConfig();

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	QObject::connect(m_ui->txtName, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtHost, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtPort, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtKeyFile, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtProxyHost, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtProxyPort, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
}

VPNConfigDialog::~VPNConfigDialog()
{
	delete m_ui;
}

bool VPNConfigDialog::isValidKeyFile(const QString& keyFileName) const
{
	if (keyFileName.isEmpty())
		return false;

	QFile keyFile(keyFileName);
	if (!keyFile.open(QIODevice::Text | QIODevice::ReadOnly))
		return false;

	QTextStream in(&keyFile);
	in.setCodec(QLatin1String("UTF-8").data()); // 配置文件采用UTF-8编码
	const QString key = in.readAll().trimmed();

	keyFile.close();

	int startIndex = key.indexOf(QLatin1String("BEGIN OpenVPN Static key"), Qt::CaseInsensitive);
	int endIndex = key.indexOf(QLatin1String("END OpenVPN Static key"), Qt::CaseInsensitive);

	return startIndex != -1 && endIndex != -1 && (endIndex - startIndex) > 512;
}

VPNConfig* VPNConfigDialog::getVPNConfig()
{
	if (!config)
		config = new VPNConfig();

	config->setName(m_ui->txtName->text());

	QString host = m_ui->txtHost->text();
	ServerEndpoint::Potocol protocol = ServerEndpoint::string2Protocol(m_ui->comboProtocol->currentText());
	if (host.indexOf(":") >= 0) {
		if (protocol == ServerEndpoint::Udp)
			protocol = ServerEndpoint::Udp6;
		else if (protocol == ServerEndpoint::Tcp)
			protocol = ServerEndpoint::Tcp6;
	}

	QList<ServerEndpoint> remotes;
	remotes.append(ServerEndpoint(host, m_ui->txtPort->text().toUShort(), protocol));
	config->setServerEndpoints(remotes);

	VPNConfig::AuthOptions authOptions = config->getAuthOptions();
	authOptions &= ~(VPNConfig::AutoProbe | VPNConfig::EnablePassword | VPNConfig::DisablePassword);
	quint32 currData = m_ui->comboPassAuth->currentData().toUInt();
	if (currData == static_cast<quint32>(VPNConfig::AutoProbe))
		authOptions |= VPNConfig::AutoProbe;
	else if (currData == static_cast<quint32>(VPNConfig::EnablePassword))
		authOptions |= VPNConfig::EnablePassword;
	else if (currData == static_cast<quint32>(VPNConfig::DisablePassword))
		authOptions |= VPNConfig::DisablePassword;
	config->setAuthOptions(authOptions);

	if (m_ui->comboTlsVersion->currentIndex() > 0)
		config->setTlsVersion(m_ui->comboTlsVersion->currentText());
	else
		config->setTlsVersion(QLatin1String(""));

	if (m_ui->comboCipher->currentIndex() > 0)
		config->setCipher(m_ui->comboCipher->currentText());
	else
		config->setCipher(QLatin1String(""));

	if (m_ui->comboAuth->currentIndex() > 0)
		config->setAuth(m_ui->comboAuth->currentText());
	else
		config->setAuth(QLatin1String(""));

	if (m_ui->ckTLSAuth->isChecked()) {
		config->getTLSAuth().setFileName(m_ui->txtKeyFile->text());
		config->getTLSAuth().setAuth(m_ui->comboTlsAuth->currentText());
		int direction = KEY_DIRECTION_BIDIRECTIONAL;
		if (m_ui->rbNormal->isChecked())
			direction = KEY_DIRECTION_NORMAL;
		else if (m_ui->rbInverse->isChecked())
			direction = KEY_DIRECTION_INVERSE;
		config->getTLSAuth().setDirection(direction);
	} else {
		config->getTLSAuth().setFileName(QLatin1String(""));
		config->getTLSAuth().setAuth(QLatin1String("SHA1"));
		config->getTLSAuth().setDirection(KEY_DIRECTION_BIDIRECTIONAL);
	}

	if (m_ui->ckProxy->isChecked()) {
		config->setEnableProxy(true);
		if (m_ui->rbSystem->isChecked())
			config->setProxyType(VPNConfig::System);
		else if (m_ui->rbHttp->isChecked())
			config->setProxyType(VPNConfig::Http);
		else
			config->setProxyType(VPNConfig::Socks);
		config->setProxyHost(m_ui->txtProxyHost->text());
		config->setProxyPort(m_ui->txtProxyPort->text().toUShort());
	} else {
		config->setEnableProxy(false);
		config->setProxyType(VPNConfig::NoneProxy);
		config->setProxyHost(QLatin1String(""));
		config->setProxyPort(0);
	}

	return config;
}

void VPNConfigDialog::setVPNConfig(VPNConfig *config)
{
	if (config) {
		m_ui->txtName->setText(config->getName());

		ServerEndpoint remote;
		if (!config->getServerEndpoints().isEmpty())
			remote = config->getServerEndpoints().at(0);

		m_ui->txtHost->setText(remote.getHost());
		m_ui->txtPort->setText(QString::number(remote.getPort()));

		int index = m_ui->comboProtocol->findText(ServerEndpoint::protocol2String(remote.getProtocol()),
			Qt::MatchFixedString);
		m_ui->comboProtocol->setCurrentIndex(index > 0 ? index : 0);

		index = m_ui->comboTlsVersion->findText(config->getTlsVersion(), Qt::MatchFixedString);
		m_ui->comboTlsVersion->setCurrentIndex(index > 0 ? index : 0);

		index = m_ui->comboCipher->findText(config->getCipher(), Qt::MatchFixedString);
		m_ui->comboCipher->setCurrentIndex(index > 0 ? index : 0);

		index = m_ui->comboAuth->findText(config->getAuth(), Qt::MatchFixedString);
		m_ui->comboAuth->setCurrentIndex(index > 0 ? index : 0);

		quint32 currData = static_cast<quint32>(VPNConfig::NoneOption);
		if (config->getAuthOptions() & VPNConfig::AutoProbe)
			currData = static_cast<quint32>(VPNConfig::AutoProbe);
		else if (config->getAuthOptions() & VPNConfig::EnablePassword)
			currData = static_cast<quint32>(VPNConfig::EnablePassword);
		else
			currData = static_cast<quint32>(VPNConfig::DisablePassword);
		index = m_ui->comboPassAuth->findData(currData);
		m_ui->comboPassAuth->setCurrentIndex(index > 0 ? index : 0);

		if (!config->getTLSAuth().isEmpty()) {
			m_ui->ckTLSAuth->setChecked(true);
			m_ui->rbBidirectional->setEnabled(true);
			m_ui->rbBidirectional->setChecked(config->getTLSAuth().getDirection() == KEY_DIRECTION_BIDIRECTIONAL);
			m_ui->rbNormal->setEnabled(true);
			m_ui->rbNormal->setChecked(config->getTLSAuth().getDirection() == KEY_DIRECTION_NORMAL);
			m_ui->rbInverse->setEnabled(true);
			m_ui->rbInverse->setChecked(config->getTLSAuth().getDirection() == KEY_DIRECTION_INVERSE);

			m_ui->lblTlsAuth->setEnabled(true);
			m_ui->comboTlsAuth->setEnabled(true);
			index = m_ui->comboTlsAuth->findText(config->getTLSAuth().getAuth(), Qt::MatchFixedString);
			m_ui->comboTlsAuth->setCurrentIndex(index > 0 ? index : 0);

			QString keyFile = config->getPath() + QLatin1Char('/') + config->getTLSAuth().getFileName();
			if (QFile::exists(keyFile))
				m_ui->txtKeyFile->setText(keyFile);
			m_ui->txtKeyFile->setEnabled(true);
			m_ui->cmdSelKeyFile->setEnabled(true);
		}

		if (config->isEnableProxy()) {
			m_ui->ckProxy->setChecked(true);
			m_ui->rbSystem->setEnabled(true);
			m_ui->rbSystem->setChecked(VPNConfig::System == config->getProxyType());
			// HTTP代理仅支持TCP协议
			m_ui->rbHttp->setEnabled(remote.getProtocol() == ServerEndpoint::Tcp);
			m_ui->rbHttp->setChecked(VPNConfig::Http == config->getProxyType());
			m_ui->rbSocks->setEnabled(true);
			m_ui->rbSocks->setChecked(VPNConfig::Socks == config->getProxyType());

			if (VPNConfig::System != config->getProxyType()) {
				m_ui->lblProxyHost->setEnabled(true);
				m_ui->txtProxyHost->setEnabled(true);
				m_ui->txtProxyHost->setText(config->getProxyHost());
				m_ui->lblProxyPort->setEnabled(true);
				m_ui->txtProxyPort->setEnabled(true);
				m_ui->txtProxyPort->setText(QString::number(config->getProxyPort()));
			}
		}
	}

	this->config = config;
}

void VPNConfigDialog::changeEvent(QEvent *e)
{
	switch (e->type()) {
	case QEvent::LanguageChange:
		m_ui->retranslateUi(this);
#ifdef FIX_OK_CANCEL_TR
		if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
			m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
		if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
			m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
		break;
	default:
		break;
	}

	QDialog::changeEvent(e);
}

void VPNConfigDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void VPNConfigDialog::checkVPNConfig()
{
	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (okButton) {
		bool ok = !m_ui->txtName->text().isEmpty() && !m_ui->txtHost->text().isEmpty() &&
			!m_ui->txtPort->text().isEmpty() && (!m_ui->ckTLSAuth->isChecked() || 
			!m_ui->txtKeyFile->text().isEmpty()) &&
			(!m_ui->ckProxy->isChecked() || m_ui->rbSystem->isChecked() ||
			(!m_ui->txtProxyHost->text().isEmpty() && !m_ui->txtProxyPort->text().isEmpty()));
		okButton->setEnabled(ok);
	}
}

void VPNConfigDialog::done(int r)
{
	if (QDialog::Accepted == r) {
		// 配置名不允许重复
		QListIterator<VPNConfig> i(configMgrProxy->list());
		while (i.hasNext()) {
			const VPNConfig x = i.next();
			if (m_ui->txtName->text().compare(x.getName(), Qt::CaseSensitive) == 0) {
				if (!config || config->getId() != x.getId()) {
					MessageBoxUtil::error(this, VPN_CLIENT_VER_PRODUCTNAME_STR,
						tr("VPN config") + " " + m_ui->txtName->text() + " " + tr("already exist!"));
					return;
				}
			}
		}

		// 检查key文件
		if (m_ui->ckTLSAuth->isChecked()) {
			if (!isValidKeyFile(m_ui->txtKeyFile->text())) {
				MessageBoxUtil::error(this, VPN_CLIENT_VER_PRODUCTNAME_STR, tr("Key file is invalid"));
				return;
			}
		}
	}

	QDialog::done(r);
}

void VPNConfigDialog::on_btnAdvanced_clicked()
{
	if (m_ui->btnAdvanced->isChecked())
		m_ui->btnAdvanced->setIcon(QIcon(QStringLiteral(":/images/adv_closed.png")));
	else
		m_ui->btnAdvanced->setIcon(QIcon(QStringLiteral(":/images/adv_expand.png")));

	this->adjustSize();
}

void VPNConfigDialog::on_ckTLSAuth_clicked()
{
	m_ui->cmdSelKeyFile->setEnabled(m_ui->ckTLSAuth->isChecked());
	m_ui->txtKeyFile->setEnabled(m_ui->ckTLSAuth->isChecked());
	m_ui->lblTlsAuth->setEnabled(m_ui->ckTLSAuth->isChecked());
	m_ui->comboTlsAuth->setEnabled(m_ui->ckTLSAuth->isChecked());
	m_ui->rbBidirectional->setEnabled(m_ui->ckTLSAuth->isChecked());
	m_ui->rbNormal->setEnabled(m_ui->ckTLSAuth->isChecked());
	m_ui->rbInverse->setEnabled(m_ui->ckTLSAuth->isChecked());

	checkVPNConfig();
}

void VPNConfigDialog::on_cmdSelKeyFile_clicked()
{
	const QString keyFileName = QFileDialog::getOpenFileName(this, tr("Select TLS auth key file"),
		Settings::instance()->getLastAccessPath(), tr("Key File (*.key *.pem);;All Files (*.*)"));

	if (!keyFileName.isEmpty()) {
		if (isValidKeyFile(keyFileName)) {
			m_ui->txtKeyFile->setText(QDir::toNativeSeparators(keyFileName));
			Settings::instance()->setLastAccessPath(QFileInfo(keyFileName).absolutePath());
		} else {
			MessageBoxUtil::error(this, tr("Select Key file"), tr("Selected file isn't valid Key file"));
		}
	}
}

void VPNConfigDialog::on_comboProtocol_currentTextChanged(const QString &text)
{
	// HTTP代理仅支持TCP协议
	if (text.compare(ServerEndpoint::protocol2String(ServerEndpoint::Tcp), Qt::CaseInsensitive) != 0) {
		if (m_ui->rbHttp->isChecked())
			m_ui->rbSystem->setChecked(true);
		m_ui->rbHttp->setEnabled(false);
	} else {
		m_ui->rbHttp->setEnabled(m_ui->ckProxy->isChecked());
	}
}

void VPNConfigDialog::on_ckProxy_clicked()
{
	m_ui->rbSystem->setEnabled(m_ui->ckProxy->isChecked());
	// HTTP代理仅支持TCP协议
	if (m_ui->comboProtocol->currentText().compare(ServerEndpoint::protocol2String(ServerEndpoint::Tcp),
			Qt::CaseInsensitive) != 0) {
		if (m_ui->rbHttp->isChecked())
			m_ui->rbSystem->setChecked(true);
		m_ui->rbHttp->setEnabled(false);
	} else {
		m_ui->rbHttp->setEnabled(m_ui->ckProxy->isChecked());
	}
	m_ui->rbSocks->setEnabled(m_ui->ckProxy->isChecked());

	m_ui->lblProxyHost->setEnabled(m_ui->ckProxy->isChecked() && !m_ui->rbSystem->isChecked());
	m_ui->txtProxyHost->setEnabled(m_ui->ckProxy->isChecked() && !m_ui->rbSystem->isChecked());
	m_ui->lblProxyPort->setEnabled(m_ui->ckProxy->isChecked() && !m_ui->rbSystem->isChecked());
	m_ui->txtProxyPort->setEnabled(m_ui->ckProxy->isChecked() && !m_ui->rbSystem->isChecked());

	checkVPNConfig();
}

void VPNConfigDialog::on_rbGroupProxy_buttonToggled(QAbstractButton *button, bool checked)
{
	if (button == m_ui->rbSystem) {
		m_ui->lblProxyHost->setEnabled(m_ui->ckProxy->isChecked() && !checked);
		m_ui->txtProxyHost->setEnabled(m_ui->ckProxy->isChecked() && !checked);
		m_ui->lblProxyPort->setEnabled(m_ui->ckProxy->isChecked() && !checked);
		m_ui->txtProxyPort->setEnabled(m_ui->ckProxy->isChecked() && !checked);
	}

	checkVPNConfig();
}

void VPNConfigDialog::onTextChanged(const QString& text)
{
	Q_UNUSED(text);

	checkVPNConfig();
}
