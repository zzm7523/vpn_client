#include <QShowEvent>
#include <QPushButton>

#include "config/version.h"
#include "common/common.h"
#include "common/dialog_util.h"
#include "progress_dialog.h"
#include "ui_progress_dialog.h"

ProgressDialog::ProgressDialog(QWidget *parent, const QString& windowTitle, const QString& labelText)
	: QDialog(parent), m_ui(new Ui::ProgressDialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);
	m_ui->label->setText(labelText);
	setResult(QDialog::Accepted);	// ±ØÐëÉèÖÃÎªQDialog::Accepted

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
}

ProgressDialog::~ProgressDialog()
{
	delete m_ui;
}

void ProgressDialog::changeEvent(QEvent *e)
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

void ProgressDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}
