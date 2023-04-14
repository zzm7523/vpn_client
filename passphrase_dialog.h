#ifndef __PRIVATE_KEY_PASSPHRASE_H__
#define __PRIVATE_KEY_PASSPHRASE_H__

#include "config/config.h"

#include <QDialog>

namespace Ui {
	class PassphraseDialog;
}

class PassphraseDialog : public QDialog
{
	Q_OBJECT
public:
	PassphraseDialog(QWidget *parent, const QString& windowTitle, const QString& description, const QString& pathName);
	~PassphraseDialog();

	void setDescription(const QString& description);

	void clearPassphrase();

	QString getPassphrase() const;

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void on_txtPassword_textChanged(const QString& text);

private:
	Ui::PassphraseDialog *m_ui;

};

#endif
