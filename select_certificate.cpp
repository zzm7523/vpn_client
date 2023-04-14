#include <QShowEvent>
#include <QTimer>
#include <QDir>
#include <QFile>
#include <QDebug>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/passphrase_generator.h"
#include "common/cipher.h"
#include "common/x509_certificate_info.h"
#include "common/x509_certificate_util.h"
#include "common/encrypt_device_manager.h"

#include "select_certificate.h"
#include "ui_select_certificate.h"
#include "certificate_detail.h"
#include "settings.h"

X509CertificateInfoWidget::X509CertificateInfoWidget(QWidget *_parent, QListWidgetItem *_item, X509CertificateInfo *_cert_info)
	: QWidget(_parent), item(_item), cert_info(_cert_info)
{
	QLabel *lblPixmap = new QLabel();
	lblPixmap->setPixmap(QPixmap(QLatin1String(":/images/certificate.png")));

	X509 *x509_cert = cert_info->getCertificate();
	QLabel *lblFriendlyName = new QLabel(X509CertificateUtil::get_friendly_name(x509_cert));
	QLabel *lblIssuer = new QLabel(tr("issuer:") + QLatin1String(" ") +
		X509CertificateUtil::get_issuer_friendly_name(x509_cert));

	QString valid_time(tr("valid time:") + QLatin1String(" "));
	const QDateTime not_before = X509CertificateUtil::get_not_before(x509_cert);
	const QDateTime not_after = X509CertificateUtil::get_not_after(x509_cert);
	valid_time.append(not_before.toString(QLatin1String("yyyy/MM/dd"))).append(QLatin1String(" ")).append(tr("to"))
		.append(QLatin1String(" ")).append(not_after.toString(QLatin1String("yyyy/MM/dd")));
	QLabel *lblValidTime = new QLabel(valid_time);

	this->button = new QToolButton();
	this->button->setText(tr("Show certificate"));
	this->button->setVisible(false);
	const QLatin1String buttonStyle = QLatin1String(
		"QToolButton {font:75 8pt 'Tahoma'; color:rgb(16, 37, 127); text-align:left; border:none; text-decoration:none;}"
		"QToolButton:hover {color:rgb(116, 137, 127); text-decoration:underline;};");
	this->button->setStyleSheet(buttonStyle);
	this->button->setCursor(Qt::PointingHandCursor);
	this->button->setFocusPolicy(Qt::StrongFocus);
	this->button->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
	QObject::connect(this->button, SIGNAL(clicked()), this, SLOT(showCertificateDetail()));

	QHBoxLayout *hLayout = new QHBoxLayout(this);
	hLayout->addWidget(lblPixmap);
	hLayout->setSpacing(6);
	hLayout->setContentsMargins(-1, 3, -1, 3);
	QVBoxLayout *vLayout = new QVBoxLayout();
	vLayout->setSpacing(0);
	vLayout->setContentsMargins(-1, 0, -1, 0);
	hLayout->addLayout(vLayout);
	vLayout->addWidget(lblFriendlyName);
	vLayout->addWidget(lblIssuer);
	vLayout->addWidget(lblValidTime);
	vLayout->addWidget(button);
	QSpacerItem *hSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
	hLayout->addItem(hSpacer);

	this->adjustSize();
	this->item->setSizeHint(this->sizeHint());
}

X509CertificateInfoWidget::~X509CertificateInfoWidget()
{
}

QListWidgetItem* X509CertificateInfoWidget::getItem() const
{
	return item;
}

X509CertificateInfo* X509CertificateInfoWidget::getCertificateInfo() const
{
	return cert_info;
}

void X509CertificateInfoWidget::click(QListWidgetItem *item)
{
	this->button->setVisible(this->item == item);
	QLayout *layout = this->layout();
	if (layout) {
		layout->invalidate();
		layout->activate();
	}
	this->adjustSize();
	this->item->setSizeHint(this->sizeHint());
}

void X509CertificateInfoWidget::showCertificateDetail()
{
	CertificateDetail certDetail(qobject_cast<QWidget*>(this), CertificateDetail::tr("X509 certificate"));
	QList<X509*> certChain;
	certChain.append(cert_info->getCertificate());
	certDetail.setCertChain(certChain);
	certDetail.exec();
}

SelectCertificate::SelectCertificate(QWidget *_parent, const QString& _windowTitle, const QString& _x509UserNameField,
		const QString& _tlsVersion, const QStringList& _keyTypes, const QStringList& _issuers)
	: QDialog(_parent), m_ui(new Ui::SelectCertificate), x509UserNameField(_x509UserNameField), tlsVersion(_tlsVersion),
	keyTypes(_keyTypes), issuers(_issuers), scanMyStoreNum(0), selected_cert_info(NULL)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(_windowTitle);

	m_ui->listCertInfos->clear();
	m_ui->listCertInfos->setSelectionMode(QAbstractItemView::SingleSelection);

	qDebug() << "x509UserNameField=" << x509UserNameField << ", tlsVersion=" << tlsVersion
		<< ", keyTypes=" << keyTypes << ", issuers=" << issuers << "\n";

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	// 不需要刷新按钮
	m_ui->cmdRefresh->setVisible(false);

#ifdef ENABLE_GUOMI
	loadCandidateCertificates(EncryptDeviceManager::instance()->getProviderName(), false);
	QObject::connect(EncryptDeviceManager::instance(), SIGNAL(deviceCurrentList(const QString&, const QStringList&, qint64)),
		this, SLOT(loadCandidateCertificates(const QString&)));
	// 不需要发送扫描加密设备事件, !!系统会自动追踪加密设备插拔事件
#else
	loadCandidateCertificates();
#endif
}

SelectCertificate::~SelectCertificate()
{
	freeX509CertificateInfos(this->all_device_certs);
	freeX509CertificateInfos(this->all_p12_certs);
	freeX509CertificateInfos(this->all_mystore_certs);
	delete m_ui;
}

X509CertificateInfo* SelectCertificate::getCertificateInfo() const
{
	return selected_cert_info;
}

bool SelectCertificate::hasCertificateInfo(X509CertificateInfo *cert_info)
{
	if (cert_info) {
		X509CertificateInfo *x_cert_info;

		QListIterator<X509CertificateInfo*> id(all_device_certs);
		while (id.hasNext()) {
			x_cert_info = id.next();
			if (x_cert_info && *x_cert_info == *cert_info)
				return true;
		}

		QListIterator<X509CertificateInfo*> ip(all_p12_certs);
		while (ip.hasNext()) {
			x_cert_info = ip.next();
			if (x_cert_info && *x_cert_info == *cert_info)
				return true;
		}

		QListIterator<X509CertificateInfo*> im(all_mystore_certs);
		while (im.hasNext()) {
			x_cert_info = im.next();
			if (x_cert_info && *x_cert_info == *cert_info)
				return true;
		}
	}
	return false;
}

void SelectCertificate::done(int r)
{
	if (r == QDialog::Accepted) {
		QListWidgetItem *item = m_ui->listCertInfos->currentItem();
		if (item) {
			QWidget *widget = m_ui->listCertInfos->itemWidget(item);
			if (widget) {
				X509CertificateInfoWidget *info_widget = dynamic_cast<X509CertificateInfoWidget*>(widget);
				if (info_widget)
					selected_cert_info = info_widget->getCertificateInfo();
			}
		}
	}

	QDialog::done(r);
}

void SelectCertificate::on_ckAllCert_stateChanged(int state)
{
	if (state == Qt::Unchecked || state == Qt::Checked) {
#ifdef ENABLE_GUOMI
		loadCandidateCertificates(EncryptDeviceManager::instance()->getProviderName(), false);
#else
		loadCandidateCertificates();
#endif
	}
}

void SelectCertificate::on_cmdRefresh_clicked()
{
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

#ifdef ENABLE_GUOMI
	// 扫描加密设备
	EncryptDeviceManager::instance()->enumDevice();
#else
	// 重新加载, 用户可能插入基于CSP的加密设备
	loadCandidateCertificates();
#endif

	QApplication::processEvents();
	QApplication::restoreOverrideCursor();
}

void SelectCertificate::changeEvent(QEvent *e)
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

void SelectCertificate::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

#ifdef ENABLE_GUOMI
#ifdef _WIN32
void SelectCertificate::timerSacnMyStore()
{
	// CryptAPI 不支持任意长度哈西签名, 不能在GMTLS协议中使用, 不能在TLSv1.3, TLSv1.2中使用
	if (!requre_any_length_sign(tlsVersion.toLocal8Bit().constData())) {
		QMap<X509*, QString> cert_map = X509CertificateUtil::load_from_mscapi(QLatin1String("MY"));
		int old_cert_num = all_mystore_certs.size();
		int new_cert_num = cert_map.size();

		// MY Store证书数量发生变化, 说明设备已向MY Store成功注册了证书
		if (old_cert_num != new_cert_num) {
			freeX509CertificateInfos(all_mystore_certs);
			all_mystore_certs.clear();

			X509CertificateInfo *cert_info;
			QMutableMapIterator<X509*, QString> im(cert_map);
			while (im.hasNext()) {
				im.next();
				cert_info = new X509CertificateInfo(im.key(), MS_CRYPTAPI_SOURCE, im.value());
				all_mystore_certs.append(cert_info);
			}
			X509CertificateUtil::free_all_cert(cert_map);

			updateUI();

		} else {
			// MY Store证书数量未发生变化, 继续调度扫描
			if (++scanMyStoreNum < MAX_SCAN_MY_STORE_NUM)
				QTimer::singleShot(1000, this, SLOT(timerSacnMyStore()));
		}
	}
}
#endif

void SelectCertificate::loadCandidateCertificates(const QString& providerName, bool plug)
#else
void SelectCertificate::loadCandidateCertificates()
#endif
{
	X509CertificateInfo *cert_info;

#ifdef ENABLE_GUOMI
	// load from encrypt device
	freeX509CertificateInfos(all_device_certs);
	all_device_certs.clear();

	if (!providerName.isEmpty()) {
		const QString libPath = QDir(QApplication::applicationDirPath()).absoluteFilePath(QLatin1String("lib"));
		QMap<X509*, QString> cert_map = X509CertificateUtil::load_from_encrypt_device(libPath, providerName);
		QMapIterator<X509*, QString> is(cert_map);
		while (is.hasNext()) {
			is.next();
			cert_info = new X509CertificateInfo(is.key(), ENCRYPT_DEVICE_SOURCE, is.value());
			all_device_certs.append(cert_info);
		}
		X509CertificateUtil::free_all_cert(cert_map);
	}

	// 插拔不需要重新加载 PKCS12
	if (!plug) {
#endif
		// load from pkcs12
		freeX509CertificateInfos(all_p12_certs);
		all_p12_certs.clear();

		const QByteArray secretKey = PassphraseGenerator::generatePKCS12Passphrase();
		const QDir pkcs12Dir(Settings::instance()->getAppSavePath());
		QListIterator<QString> ip(pkcs12Dir.entryList(QDir::Files, QDir::Name));

		while (ip.hasNext()) {
			const QString pkcs12File = pkcs12Dir.canonicalPath() + QLatin1Char('/') + ip.next();
			if (pkcs12File.endsWith(QLatin1String(".p12"), Qt::CaseInsensitive)) {
				X509 *cert = X509CertificateUtil::load_from_pkcs12_file(pkcs12File, secretKey);
				if (cert) {
					cert_info = new X509CertificateInfo(cert, PKCS12_FILE_SOURCE, pkcs12File);
					all_p12_certs.append(cert_info);
					X509_free(cert);
				}
			}
		}
#ifdef ENABLE_GUOMI
	}
#endif

#ifdef _WIN32
	// CryptAPI 不支持任意长度哈西签名, 不能在GMTLS协议中使用, 不能在TLSv1.3, TLSv1.2中使用
	if (!requre_any_length_sign(tlsVersion.toLocal8Bit().constData())) {
		// load from mscapi
		freeX509CertificateInfos(all_mystore_certs);
		all_mystore_certs.clear();

		X509CertificateInfo *cert_info;
		QMap<X509*, QString> cert_map = X509CertificateUtil::load_from_mscapi(QLatin1String("MY"));
		QMutableMapIterator<X509*, QString> im(cert_map);
		while (im.hasNext()) {
			im.next();
			cert_info = new X509CertificateInfo(im.key(), MS_CRYPTAPI_SOURCE, im.value());
			all_mystore_certs.append(cert_info);
		}
		X509CertificateUtil::free_all_cert(cert_map);
	}
#endif

	updateUI();

#if defined(ENABLE_GUOMI) && defined(_WIN32)
	if (!requre_any_length_sign(tlsVersion.toLocal8Bit().constData())) {
		if (!providerName.isEmpty() && EncryptDeviceManager::instance()->supportsEnrollToMY(providerName)) {
			// 加密设备需要向系统注册证书, 定时扫描MY不超过10次(间隔1秒扫描一次)
			scanMyStoreNum = 0;	// 重置scanMyStoreNum
			QTimer::singleShot(1000, this, SLOT(timerSacnMyStore()));
		}
	}
#endif
}

bool SelectCertificate::isCandidateCertificate(X509 *x509_cert)
{
	const QString userName = X509CertificateUtil::get_user_name(x509_cert, x509UserNameField);
	if (userName.isEmpty() || !X509CertificateUtil::is_tls_client(x509_cert))
		return false;

	// 过滤掉到期的证书
	const QDateTime not_before = X509CertificateUtil::get_not_before(x509_cert);
	const QDateTime not_after = X509CertificateUtil::get_not_after(x509_cert);
	const QDateTime now = QDateTime::currentDateTime();
	if (now < not_before || now > not_after)
		return false;

	if (issuers.size() == 0) {
		return true;
	} else {
		char buf[8192];
		memset (buf, 0x0, sizeof (buf));
		X509_NAME *xn = X509_get_issuer_name(x509_cert);
		X509_NAME_oneline(xn, buf, sizeof (buf));

		qDebug() << "issuer_name=" << buf;
		for (int i = 0; i < issuers.size(); ++i) {
			if (issuers.at(i).compare(QLatin1String(buf), Qt::CaseInsensitive) == 0)
				return true;
		}
		return false;
	}
}

void SelectCertificate::updateUI()
{
	X509CertificateInfo *cert_info;
	X509CertificateInfoWidget *widget = NULL, *current_widget = NULL;
	QListWidgetItem *item = NULL;

	QList<X509CertificateInfo*> all_cert_infos;
	all_cert_infos.append(all_device_certs);
	all_cert_infos.append(all_p12_certs);
	all_cert_infos.append(all_mystore_certs);

	QListIterator<X509CertificateInfo*> it(all_cert_infos);

	QObject::disconnect(m_ui->listCertInfos, SIGNAL(itemClicked(QListWidgetItem*)), 0, 0);	// 必须断开
	m_ui->listCertInfos->clear();

	while (it.hasNext()) {
		cert_info = it.next();

		if (m_ui->ckAllCert->isChecked() || isCandidateCertificate(cert_info->getCertificate())) {
			item = new QListWidgetItem(m_ui->listCertInfos);
			widget = new X509CertificateInfoWidget(this, item, cert_info);
			if (!current_widget)
				current_widget = widget;

			m_ui->listCertInfos->setItemWidget(item, widget);
			QObject::connect(m_ui->listCertInfos, SIGNAL(itemClicked(QListWidgetItem*)), widget, SLOT(click(QListWidgetItem*)));
		}
	}

	// 没有候选证书时, 无效OK按钮
	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (current_widget) {
		okButton->setEnabled(true);
		m_ui->listCertInfos->setCurrentItem(current_widget->getItem());
		selected_cert_info = current_widget->getCertificateInfo();
		current_widget->click(current_widget->getItem());

		// 双击确认选择客户证书
		QObject::connect(m_ui->listCertInfos, SIGNAL(itemDoubleClicked(QListWidgetItem*)), okButton, SLOT(click()));
	} else {
		okButton->setEnabled(false);
	}
}

void SelectCertificate::freeX509CertificateInfos(const QList<X509CertificateInfo*>& cert_infos)
{
	X509CertificateInfo *cert_info;
	QListIterator<X509CertificateInfo*> id(cert_infos);
	while (id.hasNext()) {
		cert_info = id.next();
		if (cert_info)
			delete (cert_info);
	}
}
