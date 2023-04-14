#include <QShowEvent>
#include <QPushButton>
#include <QScrollBar>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QTextCodec>

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/message_box_util.h"
#include "common/vpn_config.h"
#include "common/vpn_i_proxy.h"

#include "vpn_log_dialog.h"
#include "ui_vpn_log_dialog.h"

#include "vpn_item.h"
#include "preferences.h"

VPNLogDialog::VPNLogDialog(QWidget *parent)
	: QDialog(parent), m_ui(new Ui::VPNLogDialog), connectSequence(0), vpn_item(NULL), logFile(NULL), loading(false),
	lastFileSize(0)	
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowMaximizeButtonHint | Qt::WindowCloseButtonHint);
	// ��Ҫ����setWindowModality(...)����, ��Ҫ��ʾ��Ϊģ̬�Ի���
//	this->setWindowModality(Qt::WindowModal);

	// !!��ʾWaitingSpinnerWidgetʱ, ���������û�����
	spinner = new WaitingSpinnerWidget(this, true, false);
	spinner->setRoundness(60.0);
	spinner->setNumberOfLines(12);
	spinner->setLineLength(25);
	spinner->setLineWidth(10);
	spinner->setInnerRadius(25);
	spinner->setRevolutionsPerSecond(1);

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif
}

VPNLogDialog::~VPNLogDialog()
{
	if (logFile)
		delete logFile;
	delete m_ui;
}

void VPNLogDialog::setVPNItem(VPNItem *vpn_item)
{
	const QString& working_dir = vpn_item->getVPNConfig()->getPath();	// ����Ŀ¼���ǹ���Ŀ¼
	Q_ASSERT(!working_dir.isEmpty());

	if (logFile != NULL) {
		logFile->close();
		delete logFile;
	}

	logFile = new QFile(QDir(working_dir).absoluteFilePath(QLatin1String(VPN_LOG_FILE)));
	loading = false;
	lastFileSize = 0;
	m_ui->txtVPNLog->clear();

	this->vpn_item = vpn_item;
}

void VPNLogDialog::changeEvent(QEvent *e)
{
	const QString title = this->windowTitle();	// ���浱ǰtitle

	switch (e->type()) {
	case QEvent::LanguageChange:
		m_ui->retranslateUi(this);
		this->setWindowTitle(title);	// !! ������, titleû�з���
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

void VPNLogDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void VPNLogDialog::on_buttonBox_accepted()
{
	if (logFile != NULL) {
		logFile->close();
		delete logFile;
	}

	loading = false;
	logFile = NULL;
	lastFileSize = 0;
	m_ui->txtVPNLog->clear();
}

void VPNLogDialog::loadVPNLog()
{
	bool scheduling = true;	// �Ƿ���Ҫ�������ȼ���

	if (loading)	// ���ڼ���, ��������
		return;
	loading = true;	// ������ڼ���
	QApplication::processEvents();

	// �������µ�����, �����ϴ�������־
	if (connectSequence != vpn_item->getConnectSequence()) {
		connectSequence = vpn_item->getConnectSequence();
		m_ui->txtVPNLog->clear();
		lastFileSize = 0;
	}

	if (logFile && logFile->size() != lastFileSize) {
		if (logFile->open(QIODevice::ReadOnly | QIODevice::Text)) {
			WaitingSpinnerWidgetGuard guard(spinner); // start spinning
			const int chunkSize = 2048;
			QString buffer, chunk;	// �ֿ������־
			QTextStream in(logFile);
			in.setCodec(QLatin1String("UTF-8").data()); // ��־����UTF-8����

			if (logFile->size() < lastFileSize) {	// ��־�ļ����ض�
				in.seek(0);
				m_ui->txtVPNLog->clear();
			} else 
				in.seek(lastFileSize);	// ����, ��λ��ȡ��λ��

			// �����־�Ի���ر�, ����Ҫ��������
			while (this->isVisible() && !in.atEnd()) {
				QApplication::processEvents();
				chunk = in.read(chunkSize);
				buffer.append(chunk);
			}

			// �����־�Ի���ر�, ����Ҫ��������
			if (this->isVisible()) {
				QApplication::processEvents();
				m_ui->txtVPNLog->appendPlainText(buffer);
				lastFileSize = logFile->size();	// ��ס��ǰ�ļ���С
				logFile->close();

				QScrollBar *scroll_bar = m_ui->txtVPNLog->verticalScrollBar();
				scroll_bar->setValue(scroll_bar->maximum());
			}

		} else {
			scheduling = false;
			MessageBoxUtil::error(this, tr("VPN log"), tr("Can't open vpn log file"));
		}
	}

	loading = false;	// ��Ǽ��ؽ���

	// �����־�Ի���ر�, ����Ҫ�����־�仯
	if (this->isVisible() && scheduling) {
		QTimer::singleShot(1000, this, SLOT(loadVPNLog()));	// ÿ��ˢ��һ��
	}
}
