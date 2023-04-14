#include <QShowEvent>
#include <QPushButton>

#include "config/version.h"
#include "common/common.h"
#include "common/dialog_util.h"
#include "appinfo.h"
#include "ui_appinfo.h"

AppInfo::AppInfo(QWidget *parent, const QString& windowTitle)
	: QDialog(parent), m_ui(new Ui::AppInfo)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

	m_ui->lblName->setText(QLatin1String(VPN_CLIENT_VER_PRODUCTNAME_STR)); 
	m_ui->lblVersion->setText(QLatin1String(VPN_CLIENT_VER_PRODUCTVERSION_STR)
#ifdef ENABLE_GUOMI
		+ QLatin1String(" [") + tr("guo mi") + QLatin1String("]")
#endif
		);
	const QString href = QString("<a href='mailto:%1'>%1</a>").arg(QLatin1String(PRODUCT_BUGREPORT_STR));
	m_ui->lblEmail->setText(href);
	m_ui->lblCorp->setText(QLatin1String(VER_LEGALCOPYRIGHT_STR));

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
}

AppInfo::~AppInfo()
{
	delete m_ui;
}

void AppInfo::changeEvent(QEvent *e)
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

void AppInfo::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}
