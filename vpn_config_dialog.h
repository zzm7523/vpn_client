#ifndef __VPN_CONFIG_DIALOG_H__
#define __VPN_CONFIG_DIALOG_H__

#include "config/config.h"

#include <QDialog>
#include <QString>
#include <QAbstractButton>

#include "common/common.h"
#include "common/vpn_i_proxy.h"
#include "common/vpn_config_manager_i_proxy.h"

namespace Ui {
	class VPNConfigDialog;
}

class VPNConfigDialog : public QDialog
{
	Q_OBJECT
public:
	VPNConfigDialog(QWidget *parent, const QString& windowTitle, VPNConfig *config, VPNConfigManagerProxy *configMgrProxy);
	~VPNConfigDialog();

	bool isValidKeyFile(const QString& keyFile) const;

	VPNConfig* getVPNConfig();
	void setVPNConfig(VPNConfig *config);

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

private slots:
	void checkVPNConfig();
	void done(int r);
	void on_btnAdvanced_clicked();
	void on_ckTLSAuth_clicked();
	void on_cmdSelKeyFile_clicked();
	void on_comboProtocol_currentTextChanged(const QString &text);
	void on_ckProxy_clicked();
	void on_rbGroupProxy_buttonToggled(QAbstractButton *button, bool checked);
	void onTextChanged(const QString& text);

private:
	Ui::VPNConfigDialog *m_ui;
	VPNConfig *config;
	VPNConfigManagerProxy *configMgrProxy;

};

#endif
