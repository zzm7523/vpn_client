#include <QPushButton>
#include <QShowEvent>
#include <QDir>
#include <QApplication>

#include "change_pin_dialog.h"
#ifdef ENABLE_GUOMI
#include "ui_change_pin_dialog.h"

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/message_box_util.h"
#include "common/encrypt_device_manager.h"

#include <openssl/encrypt_device.h>

ChangePINDialog::ChangePINDialog(QWidget *parent, const QString& windowTitle)
	: QDialog(parent), m_ui(new Ui::ChangePINDialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

	m_ui->lblPrompt->setVisible(true);
	m_ui->comboContainer->clear();

	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	QObject::connect(m_ui->txtOldPIN, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtNewPIN, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));
	QObject::connect(m_ui->txtConfirmPIN, SIGNAL(textChanged(const QString&)), this,SLOT(onTextChanged(const QString&)));

	loadDeviceList(EncryptDeviceManager::instance()->getProviderName(), EncryptDeviceManager::instance()->getDeviceList());

	// 监听加密设备查拔信号
	QObject::connect(EncryptDeviceManager::instance(), SIGNAL(deviceCurrentList(const QString&, const QStringList&, qint64)),
		this, SLOT(loadDeviceList(const QString&, const QStringList&)));

	// 不需要发送扫描加密设备事件, !!系统会自动追踪加密设备插拔事件
}

ChangePINDialog::~ChangePINDialog()
{
	delete m_ui;
}

void ChangePINDialog::changeEvent(QEvent *e)
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

void ChangePINDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void ChangePINDialog::onTextChanged(const QString& text)
{
	Q_UNUSED(text);

	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (okButton) {
		okButton->setEnabled(!m_ui->comboContainer->currentText().isEmpty() &&
			!m_ui->txtOldPIN->text().isEmpty() && !m_ui->txtNewPIN->text().isEmpty() &&
			!m_ui->txtConfirmPIN->text().isEmpty());
	}
}

void ChangePINDialog::done(int r)
{
	if (QDialog::Accepted == r) {
		if (m_ui->txtNewPIN->text() != m_ui->txtConfirmPIN->text()) {
			m_ui->txtNewPIN->setFocus(Qt::OtherFocusReason);
			MessageBoxUtil::error(this, tr("Change PIN"), tr("PIN does not match"));
			return;
		} else if (m_ui->txtNewPIN->text() == m_ui->txtOldPIN->text()) {
			m_ui->txtNewPIN->setFocus(Qt::OtherFocusReason);
			MessageBoxUtil::error(this, tr("Change PIN"), tr("new PIN equal old PIN"));
			return;
		}
	}

	QDialog::done(r);
}

static void OPENSSL_STRING_free(OPENSSL_STRING str)
{
	if (str)
		OPENSSL_free(str);
}

void ChangePINDialog::loadDeviceList(const QString& providerName, const QStringList& deviceList)
{
	const QString libPath = QDir(QApplication::applicationDirPath()).absoluteFilePath(QLatin1String("lib"));
	ENCRYPT_DEVICE_PROVIDER *provider;

	m_ui->lblPrompt->setVisible(deviceList.isEmpty());
	m_ui->comboContainer->clear();
	this->providerName = providerName;
	this->adjustSize();

	if (providerName.isEmpty() || deviceList.isEmpty())
		return;

	provider = ENCRYPT_DEVICE_PROVIDER_load(qPrintable(libPath), qPrintable(providerName));
	if (provider) {
		STACK_OF(OPENSSL_STRING) *nameStack = NULL;
		QStringList appPathList;
		ENCRYPT_DEVICE *device;
		QString appPath;
		char *conPath;

		for (int i = 0; i < deviceList.size(); ++i) {
			device = ENCRYPT_DEVICE_open(provider, qPrintable(deviceList.at(i)), 0);
			if (device) {
				nameStack = sk_OPENSSL_STRING_new_null();
				if (ENCRYPT_DEVICE_CONTAINER_enum(device, nameStack)) {
					for (int j = 0; j < sk_OPENSSL_STRING_num(nameStack); ++j) {
						conPath = sk_OPENSSL_STRING_value(nameStack, j);
						appPath = extractAppPath(conPath);
						if (!appPathList.contains(appPath)) {
							appPathList.append(appPath);
							m_ui->comboContainer->addItem(appPath, conPath);
						}
					}
				}

				ENCRYPT_DEVICE_close(device);
				sk_OPENSSL_STRING_pop_free(nameStack, OPENSSL_STRING_free);
			}
		}

		ENCRYPT_DEVICE_PROVIDER_unload(provider);
	}

	QPushButton *okButton = m_ui->buttonBox->button(QDialogButtonBox::Ok);
	if (okButton) {
		okButton->setEnabled(!m_ui->comboContainer->currentText().isEmpty() &&
			!m_ui->txtOldPIN->text().isEmpty() && !m_ui->txtNewPIN->text().isEmpty() &&
			!m_ui->txtConfirmPIN->text().isEmpty());
	}
}

QString ChangePINDialog::extractAppPath(const QString& conPath) const
{
	ENCRYPT_DEVICE_PROVIDER *provider = ENCRYPT_DEVICE_PROVIDER_get();
	char *devName = NULL, *appName = NULL, *appPath = NULL;

	ENCRYPT_DEVICE_PROVIDER_parse_path(provider, qPrintable(conPath), &devName, &appName, NULL);
	appPath = ENCRYPT_DEVICE_PROVIDER_gen_path(provider, devName, appName, NULL);
	QString appPathStr(appPath);
	OPENSSL_free(devName), OPENSSL_free(appName), OPENSSL_free(appPath);
	return appPathStr;
}

QString ChangePINDialog::getProviderName() const
{
	return providerName;
}

QString ChangePINDialog::getApplicationPath() const
{
	return m_ui->comboContainer->currentText();
}

QString ChangePINDialog::getContainerPath() const
{
	return m_ui->comboContainer->currentData().toString();
}

QString ChangePINDialog::getOldPIN() const
{
	return m_ui->txtOldPIN->text();
}

QString ChangePINDialog::getNewPIN() const
{
	return m_ui->txtNewPIN->text();
}

#endif
