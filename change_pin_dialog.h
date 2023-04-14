#ifndef __CHANGE_PIN_DIALOG_H__
#define __CHANGE_PIN_DIALOG_H__

#include "config/config.h"

#ifdef ENABLE_GUOMI
#include <QDialog>
#include <QString>

namespace Ui {
	class ChangePINDialog;
}

class ChangePINDialog : public QDialog
{
	Q_OBJECT
public:
	ChangePINDialog(QWidget *parent, const QString& _windowTitle);
	~ChangePINDialog();

	QString getProviderName() const;
	QString getApplicationPath() const;
	QString getContainerPath() const;

	QString getOldPIN() const;
	QString getNewPIN() const;

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void done(int r);
	void onTextChanged(const QString& text);
	void loadDeviceList(const QString& providerName, const QStringList& deviceList);

private:
	QString extractAppPath(const QString& conPath) const;

	QString providerName;
	Ui::ChangePINDialog *m_ui;

};

#endif

#endif
