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
	// 不要调用setWindowModality(...)函数, 不要显示作为模态对话框
//	this->setWindowModality(Qt::WindowModal);

	// !!显示WaitingSpinnerWidget时, 不会阻塞用户输入
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
	const QString& working_dir = vpn_item->getVPNConfig()->getPath();	// 配置目录就是工作目录
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
	const QString title = this->windowTitle();	// 保存当前title

	switch (e->type()) {
	case QEvent::LanguageChange:
		m_ui->retranslateUi(this);
		this->setWindowTitle(title);	// !! 不完美, title没有翻译
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
	bool scheduling = true;	// 是否需要继续调度加载

	if (loading)	// 正在加载, 立即返回
		return;
	loading = true;	// 标记正在加载
	QApplication::processEvents();

	// 发起了新的连接, 清理上次连接日志
	if (connectSequence != vpn_item->getConnectSequence()) {
		connectSequence = vpn_item->getConnectSequence();
		m_ui->txtVPNLog->clear();
		lastFileSize = 0;
	}

	if (logFile && logFile->size() != lastFileSize) {
		if (logFile->open(QIODevice::ReadOnly | QIODevice::Text)) {
			WaitingSpinnerWidgetGuard guard(spinner); // start spinning
			const int chunkSize = 2048;
			QString buffer, chunk;	// 分块加载日志
			QTextStream in(logFile);
			in.setCodec(QLatin1String("UTF-8").data()); // 日志采用UTF-8编码

			if (logFile->size() < lastFileSize) {	// 日志文件被截断
				in.seek(0);
				m_ui->txtVPNLog->clear();
			} else 
				in.seek(lastFileSize);	// 增长, 定位读取的位置

			// 如果日志对话框关闭, 不需要继续处理
			while (this->isVisible() && !in.atEnd()) {
				QApplication::processEvents();
				chunk = in.read(chunkSize);
				buffer.append(chunk);
			}

			// 如果日志对话框关闭, 不需要继续处理
			if (this->isVisible()) {
				QApplication::processEvents();
				m_ui->txtVPNLog->appendPlainText(buffer);
				lastFileSize = logFile->size();	// 记住当前文件大小
				logFile->close();

				QScrollBar *scroll_bar = m_ui->txtVPNLog->verticalScrollBar();
				scroll_bar->setValue(scroll_bar->maximum());
			}

		} else {
			scheduling = false;
			MessageBoxUtil::error(this, tr("VPN log"), tr("Can't open vpn log file"));
		}
	}

	loading = false;	// 标记加载结束

	// 如果日志对话框关闭, 不需要监控日志变化
	if (this->isVisible() && scheduling) {
		QTimer::singleShot(1000, this, SLOT(loadVPNLog()));	// 每秒刷新一次
	}
}
