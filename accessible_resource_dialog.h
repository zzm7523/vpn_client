#ifndef __ACCESSIBLE_RESOURCE_DIALOG_H__
#define __ACCESSIBLE_RESOURCE_DIALOG_H__

#include "config/config.h"

#include <QDialog>
#include <QAbstractButton>
#include <QString>
#include <QList>
#include <QMap>

#include "common/accessible_resource.h"
#include "common/vpn_i.h"

namespace Ui {
	class AccessibleResourceDialog;
}

class VPNItem;

class AccessibleResourceDialog : public QDialog
{
	Q_OBJECT
public:
	AccessibleResourceDialog(QWidget *parent);
	~AccessibleResourceDialog();

	void changeEvent(QEvent *e);

public slots:
	void on_stateChanged(VPNAgentI::State state, VPNItem *vpn_item);
	void on_accessibleResourcesChanged(VPNItem *vpn_item);

protected:
	void showEvent(QShowEvent *e);
	void reinitialize();

private slots:
	void openAccessibleResource();

private:
	bool showAccessibleResource(const AccessibleResource& resource);
	QAbstractButton* createResourceToolButton(const AccessibleResource& resource);
	QString truncateToWidth(const QString& string, int maxWidth);
#ifdef _WIN32
	QString getSpecialFolderLocation(int type);
#endif

	Ui::AccessibleResourceDialog *m_ui;

	QMap<QString, QList<AccessibleResource>> vpnResourceMaps;
	QMap<QObject*, AccessibleResource> buttonResourceMaps;

};

#endif
