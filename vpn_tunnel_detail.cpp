#include <QShowEvent>
#include <QPushButton>

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/encrypt_device_manager.h"
#include "common/x509_certificate_util.h"

#include "vpn_item.h"
#include "vpn_tunnel_detail.h"
#include "ui_vpn_tunnel_detail.h"
#include "vpn_observer_servant.h"

VPNTunnelDetail::VPNTunnelDetail(QWidget *parent, const QString& windowTitle, VPNItem *_vpn_item)
	: QDialog(parent), m_ui(new Ui::VPNTunnelDetail), vpn_item(_vpn_item), durationTimeItem(NULL),
	bytesSentItem(NULL), bytesReceivedItem(NULL)
#ifdef ENABLE_GUOMI
	, encryptDeviceItem(NULL)
#endif
{
	m_ui->setupUi(this);
//	m_ui->trvDetails->setStyleSheet(QLatin1String("QTreeWidget::item{height:22px}"));
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	this->setWindowModality(Qt::WindowModal);
	this->setWindowTitle(windowTitle);

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	if (vpn_item) {
		// VPNTunnelDetail显示的是打开的设备列表, 而不是可见的设备列表; 不需要跟踪设备的插拔事件
		VPNContext *vpnContext = vpn_item->getVPNContext();
		VPNObserverServant *observerServant = dynamic_cast<VPNObserverServant*>(vpnContext->getVPNObserverI());
		if (observerServant)
			QObject::connect(observerServant, SIGNAL(statisticsChanged(VPNItem*)), this,
				SLOT(on_statisticsChanged(VPNItem*)), Qt::QueuedConnection);

		initialize(vpn_item);
	}
}

VPNTunnelDetail::~VPNTunnelDetail()
{
	delete m_ui;
}

void VPNTunnelDetail::initialize(VPNItem *vpn_item)
{
	m_ui->trvDetails->clear();
	m_ui->trvDetails->setSelectionMode(QAbstractItemView::SingleSelection);
	m_ui->trvDetails->setColumnCount(3);
	m_ui->trvDetails->setHeaderLabels(QStringList() << tr("ID") << tr("Name") << tr("Value"));
	m_ui->trvDetails->header()->hideSection(0);
	m_ui->trvDetails->header()->resizeSection(1, 160);

	VPNConfig *config = vpn_item->getVPNConfig();
	const VPNTunnel& tunnel = vpn_item->getVPNTunnel();
	const VPNStatistics& stats = vpn_item->getVPNStatistics();

	addTableRow(tr("Established time"), tunnel.getEstablishedTime().toString("yyyy-MM-dd hh:mm:ss"));
	durationTimeItem = addTableRow(tr("Duration time"), formatDurationTime(tunnel.getEstablishedTime()));

	bytesSentItem = addTableRow(tr("Bytes Sent"), formatTraffic(stats.getWriteBytes()));
	bytesReceivedItem = addTableRow(tr("Bytes Received"), formatTraffic(stats.getReadBytes()));

	if (tunnel.getTunDeviceType() == VPNTunnel::TAP)
		addTableRow(tr("Virtual device type"), tr("TAP"));
	else
		addTableRow(tr("Virtual device type"), tr("TUN"));

//	addTableRow(tr("Virtual gateway"), tunnel.getVirtualGateway());
	addTableRow(tr("Virtual IPv4 address"), tunnel.getVirtualIPv4Addr());
	if (!tunnel.getVirtualIPv6Addr().isEmpty())
		addTableRow(tr("Virtual IPv6 address"), tunnel.getVirtualIPv6Addr());

	addTableRow(tr("Remote host"), tunnel.getServerEndpoint().getHost());
	addTableRow(tr("Transfer port"), QString::number(tunnel.getServerEndpoint().getPort()));
	addTableRow(tr("Encapsulation protocol"), ServerEndpoint::protocol2String(tunnel.getServerEndpoint().getProtocol()));
	if (tunnel.getFragment() > 0)
		addTableRow(tr("Packet fragment"), QString::number(tunnel.getFragment()));

	QPair<int, int> keepAlive = tunnel.getKeepAlive();
	if (keepAlive.first > 0 && keepAlive.second > 0)
		addTableRow(tr("Keep alive"), QString("%1, %2").arg(keepAlive.first).arg(keepAlive.second));

	if (!config->getTLSAuth().isEmpty()) {
		const TLSAuth &auth = config->getTLSAuth();
		QString text(auth.getAuth());
		if (auth.getDirection() == KEY_DIRECTION_BIDIRECTIONAL)
			text.append(" ").append(tr("Bidirectional"));
		else if (auth.getDirection() == KEY_DIRECTION_NORMAL)
			text.append(" ").append(tr("Normal"));
		else
			text.append(" ").append(tr("Inverse"));
		text.append(" ").append(auth.getFileName());
		addTableRow(tr("TLS auth"), text);
	}

	addTableRow(tr("Cipher"), tunnel.getCipher());
	addTableRow(tr("Auth"), tunnel.getAuth());
	if (tunnel.getCompressionOption() == VPNTunnel::ADAPTIVE)
		addTableRow(tr("Compression"), QLatin1String("ADAPTIVE"));
	else if (tunnel.getCompressionOption() == VPNTunnel::YES)
		addTableRow(tr("Compression"), QLatin1String("YES"));
	else
		addTableRow(tr("Compression"), QLatin1String("NO"));

	if (!config->getCredentials().getUserName().isEmpty())
		addTableRow(tr("User name"), config->getCredentials().getUserName());
	const X509CertificateInfo &certInfo = config->getCredentials().getCertificateInfo();

	if (certInfo.getCertificate())
		addTableRow(tr("Client certificate"), X509CertificateUtil::get_friendly_name(certInfo.getCertificate()));

	// VPNTunnelDetail显示的是打开的设备列表, 而不是可见的设备列表; 不需要跟踪设备的插拔事件
#ifdef ENABLE_GUOMI
	if (!tunnel.getOpenedEncryptDevices().isEmpty())
		encryptDeviceItem = addTableRow(tr("Opened Encrypt device"), tunnel.getOpenedEncryptDevices().join(','));
#endif
}

QTreeWidgetItem* VPNTunnelDetail::addTableRow(const QString& name, const QString& value)
{
	QTreeWidgetItem *item = new QTreeWidgetItem();
	item->setText(1, name);
	item->setText(2, value);
	m_ui->trvDetails->addTopLevelItem(item);
	return item;
}

QString VPNTunnelDetail::formatDurationTime(const QDateTime& establishedTime)
{
	qint64 durationSecs = establishedTime.secsTo(QDateTime::currentDateTime());

	qint32 day = durationSecs / (24 * 3600);
	durationSecs -= day * (24 * 3600);

	qint32 hh = durationSecs / 3600;
	durationSecs -= hh * 3600;

	qint32 mm = durationSecs / 60;
	durationSecs -= mm * 60;

	qint32 ss = durationSecs;

	QString text;

	if (day > 0)
		text.append(QString::number(day)).append(" ").append(tr("day")).append(" ");

	if (hh < 10)
		text.append("0");
	text.append(QString::number(hh)).append(":");
	if (mm < 10)
		text.append("0");
	text.append(QString::number(mm)).append(":");
	if (ss < 10)
		text.append("0");
	text.append(QString::number(ss));

	return text;
}

QString VPNTunnelDetail::formatTraffic(const quint64 traffic)
{
	quint64 x_traffic = traffic;
	QStringList numbers;

	do {
		int m = x_traffic % 1000;
		x_traffic = (x_traffic - m) / 1000;

		if (x_traffic <= 0)
			numbers.prepend(QString::number(m));
		else {
			if (m < 10)
				numbers.prepend("00" + QString::number(m));
			else if (m < 100)
				numbers.prepend("0" + QString::number(m));
			else
				numbers.prepend(QString::number(m));
		}
	} while (x_traffic > 0);

	Q_ASSERT(numbers.join("").toULongLong() == traffic);

	return numbers.join(",");
}

void VPNTunnelDetail::changeEvent(QEvent *e)
{
	switch (e->type()) {
	case QEvent::LanguageChange:
		m_ui->retranslateUi(this);
#ifdef FIX_OK_CANCEL_TR
		if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
			m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
		if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
			m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
		break;
	default:
		break;
	}

	QDialog::changeEvent(e);
}

void VPNTunnelDetail::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void VPNTunnelDetail::on_statisticsChanged(VPNItem *vpn_item)
{
	Q_ASSERT(vpn_item);
	const VPNStatistics& stats = vpn_item->getVPNStatistics();

	if (durationTimeItem) {
		const VPNTunnel& tunnel = vpn_item->getVPNTunnel();
		durationTimeItem->setText(2, formatDurationTime(tunnel.getEstablishedTime()));
	}

	if (bytesSentItem) {
		bytesSentItem->setText(2, formatTraffic(stats.getWriteBytes()));
	}
	if (bytesReceivedItem) {
		bytesReceivedItem->setText(2, formatTraffic(stats.getReadBytes()));
	}
}
