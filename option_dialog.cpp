#include <QShowEvent>
#include <QPushButton>
#include <QCheckBox>

#include "common/common.h"
#include "common/dialog_util.h"
#include "settings.h"

#include "option_dialog.h"
#include "ui_option_dialog.h"

OptionDialog::OptionDialog(QWidget *parent, const QString& windowTitle)
	: QDialog(parent), m_ui(new Ui::OptionDialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);
#ifdef ENABLE_UPDATER
	m_ui->chkCheckUpdate->setVisible(true);
#else
	m_ui->chkCheckUpdate->setVisible(false);
#endif
#ifdef ENABLE_INTEGRATION
	m_ui->chkAutoStart->setMinimumSize(QSize(360, 0));
	m_ui->chkPopAccRes->setVisible(true);
#else
	m_ui->chkAutoStart->setMinimumSize(QSize(320, 0));
	m_ui->chkPopAccRes->setVisible(false);
#endif

	this->loadOption();

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
}

OptionDialog::~OptionDialog()
{
	delete m_ui;
}

void OptionDialog::changeEvent(QEvent *e)
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

void OptionDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void OptionDialog::loadOption()
{
	m_ui->chkAutoStart->setChecked(Settings::instance()->isAutoStartOnWindowsStartup());
	m_ui->chkAutoReConn->setChecked(Settings::instance()->isAutoReconnect());
	m_ui->chkAutoMinimum->setChecked(Settings::instance()->isAutoMinimum());
	m_ui->chkSaveCred->setChecked(Settings::instance()->isSaveCredential());
	m_ui->chkShowBalloon->setChecked(Settings::instance()->isShowBallonMessage());
#ifdef ENABLE_INTEGRATION
	m_ui->chkPopAccRes->setChecked(Settings::instance()->isPopupAccessibleResource());
#endif
#ifdef ENABLE_UPDATER
	m_ui->chkCheckUpdate->setChecked(Settings::instance()->isCheckUpdate());
#endif
}

void OptionDialog::saveOption()
{
	Settings::instance()->setAutoStartOnWindowsStartup(m_ui->chkAutoStart->checkState() == Qt::Checked);
	Settings::instance()->setAutoReconnect(m_ui->chkAutoReConn->checkState() == Qt::Checked);
	Settings::instance()->setAutoMinimum(m_ui->chkAutoMinimum->checkState() == Qt::Checked);
	Settings::instance()->setSaveCredential(m_ui->chkSaveCred->checkState() == Qt::Checked);
	Settings::instance()->setShowBallonMessage(m_ui->chkShowBalloon->checkState() == Qt::Checked);
#ifdef ENABLE_INTEGRATION
	Settings::instance()->setPopupAccessibleResource(m_ui->chkPopAccRes->checkState() == Qt::Checked);
#endif
#ifdef ENABLE_UPDATER
	Settings::instance()->setCheckUpdate(m_ui->chkCheckUpdate->checkState() == Qt::Checked);
#endif
}
