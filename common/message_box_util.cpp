#include <QApplication>
#include <QMessageBox>
#include <QLabel>
#include <QDialog>
#include <QTimer>
#include <QHBoxLayout>

#include "common.h"
#include "dialog_util.h"
#include "message_box_util.h"

MessageBoxUtil::MessageBoxUtil()
{
}

bool MessageBoxUtil::confirm(QWidget *parent, const QString &title, const QString &message)
{
	QMessageBox dialog(parent);

//	dialog.setIcon(QMessageBox::Question);
	dialog.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
	dialog.setDefaultButton(QMessageBox::Cancel);

#ifdef FIX_OK_CANCEL_TR
	dialog.setButtonText(QMessageBox::Ok, QDialog::tr("Ok"));
	dialog.setButtonText(QMessageBox::Cancel, QDialog::tr("Cancel"));
#endif

	dialog.setWindowTitle(title);
	dialog.setText(message);

	QApplication::setOverrideCursor(Qt::ArrowCursor);
	int result = dialog.exec();
	QApplication::restoreOverrideCursor();
	return result == QMessageBox::Ok;
}

void MessageBoxUtil::error(QWidget *parent, const QString &title, const QString &message)
{
	QMessageBox dialog(parent);

	dialog.setIcon(QMessageBox::Critical);
	dialog.setStandardButtons(QMessageBox::Ok);
	dialog.setDefaultButton(QMessageBox::Ok);

#ifdef FIX_OK_CANCEL_TR
	dialog.setButtonText(QMessageBox::Ok, QDialog::tr("Ok"));
#endif

	dialog.setWindowTitle(title);
	dialog.setText(message);

	QApplication::setOverrideCursor(Qt::ArrowCursor);
	dialog.exec();
	QApplication::restoreOverrideCursor();
//	QMessageBox::critical(parent, title, message);
}

void MessageBoxUtil::warning(QWidget *parent, const QString &title, const QString &message)
{
	QMessageBox dialog(parent);

	dialog.setIcon(QMessageBox::Warning);
	dialog.setStandardButtons(QMessageBox::Ok);
	dialog.setDefaultButton(QMessageBox::Ok);

#ifdef FIX_OK_CANCEL_TR
	dialog.setButtonText(QMessageBox::Ok, QDialog::tr("Ok"));
#endif

	dialog.setWindowTitle(title);
	dialog.setText(message);

	QApplication::setOverrideCursor(Qt::ArrowCursor);
	dialog.exec();
	QApplication::restoreOverrideCursor();
//	QMessageBox::warning(parent, title, message);
}

void MessageBoxUtil::information(QWidget *parent, const QString &title, const QString &message)
{
	QMessageBox dialog(parent);

	dialog.setIcon(QMessageBox::Information);
	dialog.setStandardButtons(QMessageBox::Ok);
	dialog.setDefaultButton(QMessageBox::Ok);

#ifdef FIX_OK_CANCEL_TR
	dialog.setButtonText(QMessageBox::Ok, QDialog::tr("Ok"));
#endif

	dialog.setWindowTitle(title);
	dialog.setText(message);

	QApplication::setOverrideCursor(Qt::ArrowCursor);
	dialog.exec();
	QApplication::restoreOverrideCursor();
//	QMessageBox::information(parent, title, message);
}

class TooltipDialog : public QDialog
{
public:
	static TooltipDialog *instance;

	TooltipDialog(QWidget *parent, const QString &tooltip);
	void setTooltip(const QString& tooltip);

protected:
	bool event(QEvent *e);
	void mousePressEvent(QMouseEvent *e);

private:
	QLabel *label;

};

TooltipDialog::TooltipDialog(QWidget *parent, const QString &tooltip)
	: QDialog(parent, Qt::Window | Qt::FramelessWindowHint), label(NULL)
{
	this->setForegroundRole(QPalette::ToolTipText);
	this->setBackgroundRole(QPalette::ToolTipBase);

	QHBoxLayout *hLayout = new QHBoxLayout(this);
	hLayout->setObjectName(QStringLiteral("hLayout"));
	hLayout->setSpacing(0);
	hLayout->setContentsMargins(0, 0, 0, 0);

	label = new QLabel(this);
	label->setObjectName(QStringLiteral("label"));
	hLayout->addWidget(label);

	label->setMargin(20);
	label->setFrameStyle(QFrame::Box);
	label->setIndent(2);
	// QLabel 要么显示文字, 要么显示图片; 不能同时显示文字和图片
	label->setText(tooltip);
}

void TooltipDialog::setTooltip(const QString& tooltip)
{
	label->setText(tooltip);
}

bool TooltipDialog::event(QEvent *e)
{
	if (e->type() == QEvent::WindowDeactivate)
		this->hide();
	return QObject::event(e);
}

void TooltipDialog::mousePressEvent(QMouseEvent *e)
{
	Q_UNUSED(e);
	this->hide();
}

TooltipDialog* TooltipDialog::instance = NULL;

void MessageBoxUtil::tooltip(QWidget *parent, const QString &tooltip, int duration)
{
	if (TooltipDialog::instance) {
		TooltipDialog::instance->hide();
		TooltipDialog::instance->setTooltip(tooltip);
	} else {
		TooltipDialog::instance = new TooltipDialog(parent, tooltip);
	}

	if (tooltip.isEmpty() || duration <= 0)
		TooltipDialog::instance->hide();
	else {
		QTimer::singleShot(duration, TooltipDialog::instance, SLOT(hide()));
		TooltipDialog::instance->adjustSize();
		TooltipDialog::instance->showNormal();
		DialogUtil::centerDialog(TooltipDialog::instance, TooltipDialog::instance->parentWidget());
	}
}
