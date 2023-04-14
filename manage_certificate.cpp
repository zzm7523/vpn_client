#include <QShowEvent>
#include <QByteArray>
#include <QTimer>
#include <QDir>
#include <QFile>
#include <QFileDialog>

#include "manage_certificate.h"
#include "ui_manage_certificate.h"
#include "select_pkcs12_dialog.h"
#include "settings.h"
#include "certificate_detail.h"

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/message_box_util.h"
#include "common/passphrase_generator.h"
#include "common/system_info.h"
#include "common/cipher.h"
#include "common/pkcs12_util.h"
#include "common/x509_certificate_info.h"
#include "common/x509_certificate_util.h"
#include "common/encrypt_device_manager.h"

ManageCertificate::ManageCertificate(QWidget *parent, const QString& windowTitle)
	: QDialog(parent), scanMyStoreNum(0), cert_index(0), m_ui(new Ui::ManageCertificate)
{
	m_ui->setupUi(this);
//	m_ui->trvClientCerts->setStyleSheet(QLatin1String("QTreeWidget::item{height:22px}"));
//	m_ui->trvIssuerCerts->setStyleSheet(QLatin1String("QTreeWidget::item{height:22px}"));
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

	QStringList header;
	header << QLatin1String("ID") << tr("Issued To") << tr("Issued By") << tr("Not Before") << tr("Not After") << tr("Source");
	m_ui->trvClientCerts->setSortingEnabled(true);
	m_ui->trvClientCerts->setSelectionMode(QAbstractItemView::SingleSelection);
	m_ui->trvClientCerts->clear();
	m_ui->trvClientCerts->setColumnCount(6);
	m_ui->trvClientCerts->setHeaderLabels(header);
	m_ui->trvClientCerts->header()->hideSection(0);
	m_ui->trvClientCerts->header()->resizeSection(1, 120);
	m_ui->trvClientCerts->header()->resizeSection(2, 120);
	m_ui->trvClientCerts->header()->resizeSection(3, 100);
	m_ui->trvClientCerts->header()->resizeSection(4, 100);

	header.clear();
	header << QLatin1String("ID") << tr("Issued To") << tr("Issued By") << tr("Not Before") << tr("Not After");
	m_ui->trvIssuerCerts->setSortingEnabled(true);
	m_ui->trvIssuerCerts->setSelectionMode(QAbstractItemView::SingleSelection);
	m_ui->trvIssuerCerts->clear();
	m_ui->trvIssuerCerts->setColumnCount(5);
	m_ui->trvIssuerCerts->setHeaderLabels(header);
	m_ui->trvIssuerCerts->header()->hideSection(0);
	m_ui->trvIssuerCerts->header()->resizeSection(1, 120);
	m_ui->trvIssuerCerts->header()->resizeSection(2, 120);

	m_ui->tabWidget->setCurrentWidget(m_ui->tabClientCerts);

	// 不需要刷新按钮
	m_ui->cmdRefresh->setVisible(false);

	this->loadCaCertificates();

#ifdef ENABLE_GUOMI
	this->loadClientCertificates(EncryptDeviceManager::instance()->getProviderName(), false);
	QObject::connect(EncryptDeviceManager::instance(), SIGNAL(deviceCurrentList(const QString&, const QStringList&, qint64)),
		this, SLOT(loadClientCertificates(const QString&)));
	// 不需要发送扫描加密设备事件, !!系统会自动追踪加密设备插拔事件
#else
	this->loadClientCertificates();
#endif
}

ManageCertificate::~ManageCertificate()
{
	X509CertificateUtil::free_all_cert(allDeviceClientCertMap_s);
	allDeviceClientCertMap_s.clear();
	allDeviceClientCertMap_i.clear();

	X509CertificateUtil::free_all_cert(allP12ClientCertMap_s);
	allP12ClientCertMap_s.clear();
	allP12ClientCertMap_s.clear();

	X509CertificateUtil::free_all_cert(allMyStoreClientCertMap_s);
	allMyStoreClientCertMap_s.clear();
	allMyStoreClientCertMap_i.clear();

	X509CertificateUtil::free_all_cert(allCaCertMap);
	allCaCertMap.clear();

	delete m_ui;
}

void ManageCertificate::loadClientCertificate(X509 *cert, const QString& source, const QString& identity, int index)
{
	Q_ASSERT(cert && index >= 0);

	QTreeWidgetItem *item = new QTreeWidgetItem();

	item->setText(1, X509CertificateUtil::get_friendly_name(cert));
	item->setData(1, Qt::UserRole, index);
	item->setText(2, X509CertificateUtil::get_issuer_friendly_name(cert));
	item->setData(2, Qt::UserRole, identity);
	item->setText(3, X509CertificateUtil::get_not_before(cert).toString(QLatin1String("yyyy-MM-dd")));
	item->setText(4, X509CertificateUtil::get_not_after(cert).toString(QLatin1String("yyyy-MM-dd")));

	if (QLatin1String(ENCRYPT_DEVICE_SOURCE) == source)
		item->setText(5, tr("encrypt device"));
	else if (QLatin1String(MS_CRYPTAPI_SOURCE) == source)
		item->setText(5, tr("windows"));
	else
		item->setText(5, tr("pkcs12 file"));
	item->setData(5, Qt::UserRole, source);

	m_ui->trvClientCerts->addTopLevelItem(item);
}

void ManageCertificate::updateTabClientCertsUI()
{
	int index = -1;
	m_ui->trvClientCerts->clear();

	QMapIterator<X509*, QString> id(allDeviceClientCertMap_s);
	while (id.hasNext()) {
		id.next();
		index = allDeviceClientCertMap_i.value(id.key());
		loadClientCertificate(id.key(), QLatin1String(ENCRYPT_DEVICE_SOURCE), id.value(), index);
	}

	QMapIterator<X509*, QString> ip(allP12ClientCertMap_s);
	while (ip.hasNext()) {
		ip.next();
		index = allP12ClientCertMap_i.value(ip.key());
		loadClientCertificate(ip.key(), QLatin1String(PKCS12_FILE_SOURCE), ip.value(), index);
	}

	QMapIterator<X509*, QString> im(allMyStoreClientCertMap_s);
	while (im.hasNext()) {
		im.next();
		index = allMyStoreClientCertMap_i.value(im.key());
		loadClientCertificate(im.key(), QLatin1String(MS_CRYPTAPI_SOURCE), im.value(), index);
	}
}

#ifdef ENABLE_GUOMI
#ifdef _WIN32
void ManageCertificate::timerSacnMyStore()
{
	QMap<X509*, QString> cert_map = X509CertificateUtil::load_from_mscapi(QLatin1String("MY"));
	int old_cert_num = allMyStoreClientCertMap_s.size();
	int new_cert_num = cert_map.size();

	// MY Store证书数量发生变化, 说明设备已向MY Store成功注册了证书
	if (old_cert_num != new_cert_num) {
		X509CertificateUtil::free_all_cert(allMyStoreClientCertMap_s);
		allMyStoreClientCertMap_s.clear();
		allMyStoreClientCertMap_i.clear();

		QMapIterator<X509*, QString> im(cert_map);
		while (im.hasNext()) {
			im.next();
			if (X509CertificateUtil::is_tls_client(im.key())) {
				allMyStoreClientCertMap_i.insert(im.key(), ++cert_index);
				allMyStoreClientCertMap_s.insert(im.key(), im.value());
			}
			else
				X509_free(im.key());	// 释放非客户端证书
		}

		updateTabClientCertsUI();

	}
	else {
		// MY Store证书数量未发生变化, 继续调度扫描
		if (++scanMyStoreNum < MAX_SCAN_MY_STORE_NUM)
			QTimer::singleShot(1000, this, SLOT(on_timer_sacnMyStore()));
	}
}
#endif

void ManageCertificate::loadClientCertificates(const QString& providerName, bool plug)
#else
void ManageCertificate::loadClientCertificates()
#endif
{
#ifdef ENABLE_GUOMI
	X509CertificateUtil::free_all_cert(allDeviceClientCertMap_s);
	allDeviceClientCertMap_s.clear();
	allDeviceClientCertMap_i.clear();

	// 加载加密设备
	if (!providerName.isEmpty()) {
		const QString libPath = QDir(QApplication::applicationDirPath()).absoluteFilePath(QLatin1String("lib"));
		QMap<X509*, QString> from_encrypt_device = X509CertificateUtil::load_from_encrypt_device(libPath, providerName);
		QMapIterator<X509*, QString> id(from_encrypt_device);

		while (id.hasNext()) {
			id.next();
			allDeviceClientCertMap_i.insert(id.key(), ++cert_index);
			allDeviceClientCertMap_s.insert(id.key(), id.value());
		}
	}

	// 加载本地PKCS12文件, 插拔不需要重新加载 PKCS12
	if (!plug) {
#endif

		X509CertificateUtil::free_all_cert(allP12ClientCertMap_s);
		allP12ClientCertMap_s.clear();
		allP12ClientCertMap_i.clear();

		X509 *cert = NULL;
		const QDir pkcs12Dir(Settings::instance()->getAppSavePath());
		const QByteArray secretKey = PassphraseGenerator::generatePKCS12Passphrase();
		QListIterator<QString> ip(pkcs12Dir.entryList(QDir::Files, QDir::Name));

		while (ip.hasNext()) {
			const QString pkcs12File = pkcs12Dir.canonicalPath() + QLatin1Char('/') + ip.next();
			if (pkcs12File.endsWith(QLatin1String(".p12"), Qt::CaseInsensitive)) {
				if (Pkcs12Util::readPkcs12(pkcs12File, secretKey, NULL, &cert, NULL)) {
					allP12ClientCertMap_i.insert(cert, ++cert_index);
					allP12ClientCertMap_s.insert(cert, pkcs12File);
				}
			}
		}
#ifdef ENABLE_GUOMI
	}
#endif

#ifdef _WIN32
	X509CertificateUtil::free_all_cert(allMyStoreClientCertMap_s);
	allMyStoreClientCertMap_s.clear();
	allMyStoreClientCertMap_i.clear();

	// 加载CertStore
	QMap<X509*, QString> from_mscapi = X509CertificateUtil::load_from_mscapi(QLatin1String("MY"));
	QMapIterator<X509*, QString> im(from_mscapi);

	while (im.hasNext()) {
		im.next();
		if (X509CertificateUtil::is_tls_client(im.key())) {
			allMyStoreClientCertMap_i.insert(im.key(), ++cert_index);
			allMyStoreClientCertMap_s.insert(im.key(), im.value());
		} else
			X509_free(im.key());	// 释放非客户端证书
	}
#endif

	updateTabClientCertsUI();

#if defined(ENABLE_GUOMI) && defined(_WIN32)
	// 加密设备需要向系统注册证书, 定时扫描MY不超过10秒(间隔1秒扫描一次)
	if (!providerName.isEmpty() && EncryptDeviceManager::instance()->supportsEnrollToMY(providerName)) {
		scanMyStoreNum = 0;	// 重置scanMyStoreNum
		QTimer::singleShot(1000, this, SLOT(timerSacnMyStore()));
	}
#endif
}

void ManageCertificate::loadCaCertificates()
{
	X509CertificateUtil::free_all_cert(allCaCertMap);
	allCaCertMap.clear();

	m_ui->trvIssuerCerts->clear();

	/*
	 * 操作系统可能采用Local8Bit字符集，也可能采用UTF-8字符集，或其它...
	 * 文件名称从QString转换成const char*时采用那个字符集不好确定
	 * 使用QFile读取证书内容到缓存(由QT做字符集处理), 使用内存BIO; 不使用文件BIO
	 */
	QFile x_file(Settings::instance()->getCAFileName());
	if (!x_file.open(QIODevice::ReadOnly))
		return;

	QByteArray mem = x_file.readAll();
	x_file.close();

	BIO *bio = BIO_new_mem_buf(mem.data(), mem.size());
	X509 *ca_cert;

	while (true) {
		ca_cert = NULL;
		if (!PEM_read_bio_X509(bio, &ca_cert, NULL, NULL)) {
			break;
		} else {
			QTreeWidgetItem *item = new QTreeWidgetItem();

			allCaCertMap.insert(++cert_index, ca_cert);
			item->setText(1, X509CertificateUtil::get_friendly_name(ca_cert));
			item->setData(1, Qt::UserRole, cert_index);
			item->setText(2, X509CertificateUtil::get_issuer_friendly_name(ca_cert));
			item->setText(3, X509CertificateUtil::get_not_before(ca_cert).toString(QLatin1String("yyyy-MM-dd")));
			item->setText(4, X509CertificateUtil::get_not_after(ca_cert).toString(QLatin1String("yyyy-MM-dd")));

			m_ui->trvIssuerCerts->addTopLevelItem(item);
		}
	}

	BIO_free(bio);
	ERR_clear_error();
}

void ManageCertificate::changeEvent(QEvent *e)
{
	switch (e->type()) {
	case QEvent::LanguageChange:
		m_ui->retranslateUi(this);
		break;
	default:
		break;
	}

	QDialog::changeEvent(e);
}

void ManageCertificate::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

bool ManageCertificate::importPkcs12(const QString& pkcs12File, const QString& protectPassword)
{
	EVP_PKEY *prvkey = NULL;
	X509 *cert = NULL;
	QList<X509*> ca;
	bool ret = false;

	if (!Pkcs12Util::readPkcs12(pkcs12File, protectPassword.toLocal8Bit(), &prvkey, &cert, &ca)) {
		MessageBoxUtil::error(this, tr("Certificate import"), tr("The password you entered is incorrect"));
		goto finish;
	}

	if (!X509CertificateUtil::is_tls_client(cert)) {
		MessageBoxUtil::error(this, tr("Certificate import"), tr("don't HTTPS client certificate"));
		goto finish;
	}

	// 如果不存在相同的Pkcs12证书, 就导入; 即使加密设备中或者Windows MY Store中已存在
	if (!X509CertificateUtil::contains(allP12ClientCertMap_s.keys(), cert)) {
		const QString uniqueFileName =
			generateUniqueFileName(Settings::instance()->getAppSavePath(), QLatin1String(".p12"));
		const QByteArray secretKey = PassphraseGenerator::generatePKCS12Passphrase();
		if (Pkcs12Util::writePkcs12(uniqueFileName, secretKey, prvkey, cert, &ca)) {
			allP12ClientCertMap_i.insert(cert, ++cert_index);
			allP12ClientCertMap_s.insert(cert, uniqueFileName);

			updateTabClientCertsUI();
			ret = true;
		}
	}

finish:
	if (prvkey)
		EVP_PKEY_free(prvkey);
	if (!ret) {
		if (cert)
			X509_free(cert);
	}
	X509CertificateUtil::free_all_cert(ca);
	return ret;
}

bool ManageCertificate::importCaCertificate(const QString& certFile)
{
	/*
	 * 操作系统可能采用Local8Bit字符集，也可能采用UTF-8字符集，或其它...
	 * 文件名称从QString转换成const char*时采用那个字符集不好确定
	 * 使用QFile读取证书内容到缓存(由QT做字符集处理), 使用内存BIO; 不使用文件BIO
	 */
	QFile x_file(certFile);
	if (!x_file.open(QIODevice::ReadOnly)) {
		MessageBoxUtil::error(this,	tr("Certificate import"), tr("Please affirm file exist"));
		return false;
	}

	QByteArray mem = x_file.readAll();
	x_file.close();

	BIO *bio = BIO_new_mem_buf(mem.data(), mem.size());
	X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!cert) {
		ERR_clear_error();
		BIO_seek(bio, 0);
		cert = d2i_X509_bio(bio, NULL);
	}
	BIO_free(bio);

	if (!cert) {
		MessageBoxUtil::error(this, tr("Certificate import"), tr("Please affirm file is certificate file"));
		return false;
	}

	if (X509CertificateUtil::contains(allCaCertMap.values(), cert)) {
		X509_free(cert);
		return false;
	}

	if (!X509CertificateUtil::is_ca(cert)) {
		MessageBoxUtil::error(this, tr("Certificate import"), tr("is not CA certificate"));
		X509_free(cert);
		return false;
	}

	QList<X509*> x509_list;
	x509_list << cert;

	if (!X509CertificateUtil::add_cert_to_file(Settings::instance()->getCAFileName(), x509_list)) {
//	if (isExistCertificate(cert, allCaCertMap) || !X509CertificateUtil::add_trusted_ca_to_system(cert)) {
		X509_free(cert);
		return false;
	}

	QTreeWidgetItem *item = new QTreeWidgetItem();
	allCaCertMap.insert(++cert_index, cert);
	item->setText(1, X509CertificateUtil::get_friendly_name(cert));
	item->setData(1, Qt::UserRole, cert_index);
	item->setText(2, X509CertificateUtil::get_issuer_friendly_name(cert));
	item->setText(3, X509CertificateUtil::get_not_before(cert).toString(QLatin1String("yyyy-MM-dd")));
	item->setText(4, X509CertificateUtil::get_not_after(cert).toString(QLatin1String("yyyy-MM-dd")));

	m_ui->trvIssuerCerts->addTopLevelItem(item);
	return true;
}

void ManageCertificate::on_cmdImport_clicked()
{
	if (m_ui->tabWidget->currentWidget() == m_ui->tabClientCerts) {
		SelectPkcs12Dialog dialog(this, SelectPkcs12Dialog::tr("Select PKCS12 file"));
		if (dialog.exec() == QDialog::Accepted) {
			const QString pkcs12File = dialog.getPkcs12File();
			const QString protectPassword = dialog.getProtectPassword();

			importPkcs12(pkcs12File, protectPassword);
		}
	} else if (m_ui->tabWidget->currentWidget() == m_ui->tabIssuerCerts) {
		const QString certFile = QFileDialog::getOpenFileName(this, tr("Select CA certificate file"),
			Settings::instance()->getLastAccessPath(), tr("X.509 Certificates (*.crt *.cer *.pem);;All Files (*.*)"));

		if (!certFile.isEmpty()) {
			importCaCertificate(certFile);
			Settings::instance()->setLastAccessPath(QFileInfo(certFile).absolutePath());
		}
	}
}

X509* ManageCertificate::getClientCertificateByIndex(int index) const
{
	X509 *cert = NULL;

	if (!cert)
		cert = allDeviceClientCertMap_i.key(index, NULL);

	if (!cert)
		cert = allP12ClientCertMap_i.key(index, NULL);

	if (!cert)
		cert = allMyStoreClientCertMap_i.key(index, NULL);

	return cert;
}

QString ManageCertificate::generateUniqueFileName(const QString& dirname, const QString& suffix)
{
	QString uniqueFileName = 
		QDir(dirname).absoluteFilePath(QDateTime::currentDateTime().toString(QLatin1String("MMyyddHHmmss")));

	char z_buf[8] = {0};
	sprintf(z_buf, "%04d", rand() % 10000);
	uniqueFileName.append(z_buf);

	if (!suffix.isEmpty())
		uniqueFileName.append(suffix);
	return uniqueFileName;
}

void ManageCertificate::on_cmdRemove_clicked()
{
	if (m_ui->tabWidget->currentWidget() == m_ui->tabClientCerts) {
		QList<QTreeWidgetItem *> selecteds_items = m_ui->trvClientCerts->selectedItems();

		if (selecteds_items.size() == 1) {
			if (MessageBoxUtil::confirm(this, tr("Certificate manage"), tr("Do you want to remove client certificate?"))) {
				int cert_index = selecteds_items.at(0)->data(1, Qt::UserRole).toInt();
				X509 *cert = getClientCertificateByIndex(cert_index);
				if (cert) {
					allDeviceClientCertMap_s.remove(cert);
					allDeviceClientCertMap_i.remove(cert);

					allP12ClientCertMap_s.remove(cert);
					allP12ClientCertMap_i.remove(cert);

					allMyStoreClientCertMap_s.remove(cert);
					allMyStoreClientCertMap_i.remove(cert);

					X509_free(cert);
				}

				const QString pkcs12FileName = selecteds_items.at(0)->data(2, Qt::UserRole).toString();
				if (!pkcs12FileName.isEmpty())
					QFile(pkcs12FileName).remove();

				QTreeWidgetItem *root_item = m_ui->trvClientCerts->invisibleRootItem();
				int item_index = m_ui->trvClientCerts->indexOfTopLevelItem(selecteds_items.at(0));
				root_item->takeChild(item_index);
			}
		}

	} else if (m_ui->tabWidget->currentWidget() == m_ui->tabIssuerCerts) {
		QList<QTreeWidgetItem *> selecteds_items = m_ui->trvIssuerCerts->selectedItems();

		if (selecteds_items.size() == 1)
		{
			if (MessageBoxUtil::confirm(this, tr("Certificate manage"), tr("Do you want to remove ca certificate?"))) {
				int cert_index = selecteds_items.at(0)->data(1, Qt::UserRole).toInt();
				X509 *ca_cert = allCaCertMap.value(cert_index, NULL);
				if (ca_cert) {
					X509CertificateUtil::remove_cert_from_file(Settings::instance()->getCAFileName(), ca_cert);
					X509_free(ca_cert);
				}
				allCaCertMap.remove(cert_index);

				QTreeWidgetItem *root_item = m_ui->trvIssuerCerts->invisibleRootItem();
				int item_index = m_ui->trvIssuerCerts->indexOfTopLevelItem(selecteds_items.at(0));
				root_item->takeChild(item_index);
			}
		}
	}
}

void ManageCertificate::on_cmdRefresh_clicked()
{
	Q_ASSERT(m_ui->tabWidget->currentWidget() == m_ui->tabClientCerts);

	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

#ifdef ENABLE_GUOMI
	// 扫描加密设备
	EncryptDeviceManager::instance()->enumDevice();
#else
	// 重新加载, 用户可能插入基于CSP的加密设备
	loadClientCertificates();
#endif

	QApplication::processEvents();
	QApplication::restoreOverrideCursor();
}

void ManageCertificate::on_cmdClose_clicked()
{
	this->close();
}

void ManageCertificate::on_tabWidget_currentChanged(int index)
{
	Q_UNUSED(index);

	if (m_ui->tabWidget->currentWidget() == m_ui->tabClientCerts) {
		QList<QTreeWidgetItem *> selecteds_items = m_ui->trvClientCerts->selectedItems();
		if (selecteds_items.size() == 1) {
			const QString source = selecteds_items.at(0)->data(5, Qt::UserRole).toString();
			m_ui->cmdRemove->setEnabled(source.compare(PKCS12_FILE_SOURCE, Qt::CaseInsensitive) == 0);
		}
		// 不需要刷新按钮
//		m_ui->cmdRefresh->setVisible(true);

	} else if (m_ui->tabWidget->currentWidget() == m_ui->tabIssuerCerts) {
		m_ui->cmdRemove->setEnabled(m_ui->trvIssuerCerts->selectedItems().size() == 1);
		// 不需要刷新按钮
//		m_ui->cmdRefresh->setVisible(false);
	}
}

void ManageCertificate::on_trvClientCerts_itemDoubleClicked(QTreeWidgetItem *item, int column)
{
	Q_UNUSED(item);
	Q_UNUSED(column);

	int cert_index = item->data(1, Qt::UserRole).toInt();
	X509 *cert = getClientCertificateByIndex(cert_index);

	if (cert) {
		CertificateDetail dialog(this, tr("X509 certificate"));
		dialog.setCertChain(QList<X509*>() << cert);
		dialog.exec();
	}
}

void ManageCertificate::on_trvIssuerCerts_itemDoubleClicked(QTreeWidgetItem *item, int column)
{
	Q_UNUSED(item);
	Q_UNUSED(column);

	int cert_index = item->data(1, Qt::UserRole).toInt();
	X509 *ca_cert = allCaCertMap.value(cert_index, NULL);

	if (ca_cert) {
		QList<X509*> certChain;
		certChain.append(ca_cert);

		CertificateDetail dialog(this, CertificateDetail::tr("X509 certificate"));
		dialog.setCertChain(certChain);
		dialog.exec();
	}
}

void ManageCertificate::on_trvClientCerts_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
	Q_UNUSED(previous);
	if (current) {
		const QString source = current->data(5, Qt::UserRole).toString();
		m_ui->cmdRemove->setEnabled(source.compare(PKCS12_FILE_SOURCE, Qt::CaseInsensitive) == 0);
	}
}

void ManageCertificate::on_trvIssuerCerts_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
	Q_UNUSED(previous);
	m_ui->cmdRemove->setEnabled(current != NULL);
}
