#ifndef __CHANGE_PASSWORD_DIALOG_H__
#define __CHANGE_PASSWORD_DIALOG_H__

#include "config/config.h"

#include <QString>
#include <QDialog>

namespace Ui {
	class ChangePasswordDialog;
}

class ChangePasswordDialog : public QDialog
{
	Q_OBJECT
public:
	ChangePasswordDialog(QWidget *parent, const QString& windowTitle);
	~ChangePasswordDialog();

	QString getOldPassword() const;
	QString getNewPassword() const;

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void done(int r);
	void onTextChanged(const QString& text);

private:
	Ui::ChangePasswordDialog *m_ui;

};

#endif
