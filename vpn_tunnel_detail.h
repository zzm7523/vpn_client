#ifndef __VPN_TUNNEL_DETAIL_H__
#define __VPN_TUNNEL_DETAIL_H__

#include "config/config.h"

#include <QDialog>
#include <QToolButton>
#include <QString>
#include <QStringList>
#include <QTreeWidgetItem>

#include "common/vpn_i.h"

namespace Ui {
	class VPNTunnelDetail;
}

class VPNItem;

class VPNTunnelDetail : public QDialog
{
	Q_OBJECT
public:
	VPNTunnelDetail(QWidget *parent, const QString& windowTitle, VPNItem *vpn_item);
	~VPNTunnelDetail();

protected:
	void changeEvent(QEvent *e);
	void showEvent(QShowEvent *e);

public slots:
	void on_statisticsChanged(VPNItem *vpn_item);

private:
	void initialize(VPNItem *item);
	QTreeWidgetItem* addTableRow(const QString& name, const QString& value);
	QString formatDurationTime(const QDateTime& establishedTime);
	QString formatTraffic(const quint64 traffic);

	Ui::VPNTunnelDetail *m_ui;
	VPNItem *vpn_item;

	QTreeWidgetItem *durationTimeItem;
	QTreeWidgetItem *bytesSentItem;
	QTreeWidgetItem *bytesReceivedItem;
#ifdef ENABLE_GUOMI
	QTreeWidgetItem *encryptDeviceItem;
#endif

};

#endif
