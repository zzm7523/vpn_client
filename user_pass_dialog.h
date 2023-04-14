#ifndef __AUTHENTICATION_DIALOG_H__
#define __AUTHENTICATION_DIALOG_H__

#include "config/config.h"

#include <QDialog>
#include <QString>

namespace Ui {
	class UserPassDialog;
}

class UserPassDialog : public QDialog
{
	Q_OBJECT
public:
	UserPassDialog(QWidget *parent, const QString& windowTitle, const QString& description, const QString& userName);
	~UserPassDialog();

	QString getUserName() const;
	QString getPassword() const;

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void onTextChanged(const QString& text);

private:
	Ui::UserPassDialog *m_ui;

};

#endif
