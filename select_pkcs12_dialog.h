#ifndef __SELECT_PKCS12_DIALOG_H__
#define __SELECT_PKCS12_DIALOG_H__

#include "config/config.h"

#include <QDialog>
#include <QString>

namespace Ui {
	class SelectPkcs12Dialog;
}

class SelectPkcs12Dialog : public QDialog
{
	Q_OBJECT
public:
	SelectPkcs12Dialog(QWidget *parent, const QString& windowTitle);
	~SelectPkcs12Dialog();

	QString getPkcs12File() const;
	QString getProtectPassword() const;

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void onTextChanged(const QString& text);
	void on_cmdPkcs12_clicked();
	void done(int r);

private:
	Ui::SelectPkcs12Dialog *m_ui;

};

#endif
