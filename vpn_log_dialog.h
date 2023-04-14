#ifndef __VPN_LOG_DIALOG_H__
#define __VPN_LOG_DIALOG_H__

#include "config/config.h"

#include <QDialog>
#include <QFile>
#include <QDateTime>

#include "widgets/waiting_spinner_widget.h"

namespace Ui {
	class VPNLogDialog;
}

class VPNItem;

class VPNLogDialog : public QDialog
{
	Q_OBJECT
public:
	VPNLogDialog(QWidget *parent);
	~VPNLogDialog();

	void changeEvent(QEvent *e);

	void setVPNItem(VPNItem *vpn_item);

public slots:
	void on_buttonBox_accepted();
	void loadVPNLog();

protected:
	void showEvent(QShowEvent *e);

private:
	Ui::VPNLogDialog *m_ui;
	WaitingSpinnerWidget *spinner;

	qint64 connectSequence;
	VPNItem *vpn_item;
	QFile *logFile;
	bool loading;
	qint64 lastFileSize;

};

#endif
