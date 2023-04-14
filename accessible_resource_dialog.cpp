#include <QApplication>
#include <QShowEvent>
#include <QMutableMapIterator>
#include <QListIterator>
#include <QMutableListIterator>
#include <QGridLayout>
#include <QProcess>
#include <QUrl>
#include <QDesktopServices>
#include <QDateTime>
#include <QPushButton>
#include <QToolButton>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#include <Iphlpapi.h>
#include <ShlObj.h>
#endif

#include "common/common.h"
#include "common/dialog_util.h"
#include "common/message_box_util.h"

#include "vpn_item.h"
#include "accessible_resource_dialog.h"
#include "ui_accessible_resource_dialog.h"

AccessibleResourceDialog::AccessibleResourceDialog(QWidget *parent)
	: QDialog(parent), m_ui(new Ui::AccessibleResourceDialog)
{
	m_ui->setupUi(this);
	this->setWindowFlags(Qt::Dialog | Qt::WindowCloseButtonHint);
	// 不要调用setWindowModality(...)函数, 不要显示作为模态对话框
//	this->setWindowModality(Qt::WindowModal);

#ifdef FIX_OK_CANCEL_TR
	if (m_ui->buttonBox->button(QDialogButtonBox::Ok))
		m_ui->buttonBox->button(QDialogButtonBox::Ok)->setText(QDialog::tr("Ok"));
	if (m_ui->buttonBox->button(QDialogButtonBox::Cancel))
		m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(QDialog::tr("Cancel"));
#endif

	reinitialize();
}

AccessibleResourceDialog::~AccessibleResourceDialog()
{
	delete m_ui;
}

QAbstractButton* AccessibleResourceDialog::createResourceToolButton(const AccessibleResource& resource)
{
	QToolButton *button = new QToolButton(this);
	if (resource.getUri().startsWith(QLatin1String("http:"), Qt::CaseInsensitive) ||
			resource.getUri().startsWith(QLatin1String("https:"), Qt::CaseInsensitive))
		button->setIcon(QIcon(QLatin1String(":/images/web_resource.png")));
	else if (resource.getUri().startsWith(QLatin1String("ftp:"), Qt::CaseInsensitive) ||
			resource.getUri().startsWith(QLatin1String("sftp:"), Qt::CaseInsensitive))
		button->setIcon(QIcon(QLatin1String(":/images/ftp_resource.png")));
	else if (resource.getUri().startsWith(QLatin1String("telnet:"), Qt::CaseInsensitive))
		button->setIcon(QIcon(QLatin1String(":/images/telnet_resource.png")));
	else if (resource.getUri().startsWith(QLatin1String("\\\\"), Qt::CaseInsensitive))
		button->setIcon(QIcon(QLatin1String(":/images/share_resource.png")));
	else
		button->setIcon(QIcon(QLatin1String(":/images/other_resource.png")));
	button->setIconSize(QSize(48, 48));

	QString name = truncateToWidth(resource.getName(), 20);
	if (name.size() != resource.getName().size())
		name = name.append(QLatin1String("..."));
	button->setText(name);
	button->setToolTip(resource.getUri());

	QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
	sizePolicy.setHorizontalStretch(0);
	sizePolicy.setVerticalStretch(0);
	sizePolicy.setHeightForWidth(button->sizePolicy().hasHeightForWidth());
	button->setSizePolicy(sizePolicy);
	// 每行显示4个资源
	button->setMinimumSize(QSize(this->width() / 4 - 18, 0));
	button->setMaximumSize(QSize(this->width() / 4 - 18, 16777215));

	QString buttonStyle = QLatin1String(
		"QToolButton {font: 75 8pt 'Tahoma'; color: rgb(16, 37, 127); text-align: left; border: none; text-decoration: none;}"
		"QToolButton:hover {color: rgb(116, 137, 127); text-decoration: underline;};");
	button->setStyleSheet(buttonStyle);
	button->setCursor(Qt::PointingHandCursor);
	button->setFocusPolicy(Qt::StrongFocus);
	button->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);

	buttonResourceMaps.insert(button, resource); // 记录QToolButton和AccessibleResource的对应关系

	QObject::connect(button, SIGNAL(clicked()), this, SLOT(openAccessibleResource()));
	return button;
}

QString AccessibleResourceDialog::truncateToWidth(const QString& string, int maxWidth)
{
	QString result;
	int width = 0;	// 假定汉字显示宽度是英文字符的两倍

	for (int i = 0; i < string.size(); ++i) {
		width += (string.at(i).unicode() < 255) ? 1 : 2;
		if (width < maxWidth)
			result.append(string.at(i));
		else
			break;
	}

	return result;
}

bool AccessibleResourceDialog::showAccessibleResource(const AccessibleResource& resource)
{
	if  (resource.getPlatform().compare(ANY_PLATFORM, Qt::CaseInsensitive) == 0)
		return true;

#if defined(Q_OS_WIN32)
	return resource.getPlatform().compare(WINDOWS_PLATFORM, Qt::CaseInsensitive) == 0;
#elif defined(Q_OS_LINUX)
	return resource.getPlatform().compare(LINUX_PLATFORM, Qt::CaseInsensitive) == 0;
#elif defined(Q_OS_MACOS)
	return resource.getPlatform().compare(MACX_PLATFORM, Qt::CaseInsensitive) == 0;
#elif defined(Q_OS_IOS)
	return resource.getPlatform().compare(IOS_PLATFORM, Qt::CaseInsensitive) == 0;
#elif defined(Q_OS_ANDROID)
	return resource.getPlatform().compare(ANDROID_PLATFORM, Qt::CaseInsensitive) == 0;
#else
	return false;
#endif
}

void AccessibleResourceDialog::reinitialize()
{
	QList<QObject*> children = m_ui->sawResources->children();
	QListIterator<QObject*> i(children);
	while (i.hasNext()) {
		delete i.next();
	}

	buttonResourceMaps.clear();

	int row = 0, column = 0;
	QVBoxLayout *verticalLayout = new QVBoxLayout(m_ui->sawResources);
	QGridLayout *gridLayout = new QGridLayout();

	gridLayout->setVerticalSpacing(24);
	verticalLayout->addLayout(gridLayout);

	QMapIterator<QString, QList<AccessibleResource> > ir(vpnResourceMaps);
	while (ir.hasNext()) {
		ir.next();

		QListIterator<AccessibleResource> ix(ir.value());
		while (ix.hasNext()) {
			const AccessibleResource& resource = ix.next();
			if (showAccessibleResource(resource)) {
				gridLayout->addWidget(createResourceToolButton(resource), row, column++, 1, 1);
				if (column > 3)	{ // 每行显示4个资源
					++row;
					column = 0;
				}
			}
		}
	}

	if (column > 0 && column < 4) {	// 当前行有资源, 单不够4个, 填充水平空白
		QSpacerItem *horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Expanding);
		gridLayout->addItem(horizontalSpacer, row, column, 1, 1);
	}

	QSpacerItem *verticalSpacer = new QSpacerItem(20, 260, QSizePolicy::Minimum, QSizePolicy::Expanding);
	verticalLayout->addItem(verticalSpacer);
}

void AccessibleResourceDialog::changeEvent(QEvent *e)
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

void AccessibleResourceDialog::showEvent(QShowEvent *e)
{
	Q_UNUSED(e);
	DialogUtil::centerDialog(this, this->parentWidget());
}

void AccessibleResourceDialog::on_stateChanged(VPNAgentI::State state, VPNItem *vpn_item)
{
	if (state == VPNAgentI::Connected) {
		;
	} else if (state == VPNAgentI::Disconnected || state == VPNAgentI::Reconnecting) {
		this->vpnResourceMaps.remove(vpn_item->getVPNConfig()->getName());
		reinitialize();
	}
}

void AccessibleResourceDialog::on_accessibleResourcesChanged(VPNItem *vpn_item)
{
	this->vpnResourceMaps.remove(vpn_item->getVPNConfig()->getName());
	this->vpnResourceMaps.insert(vpn_item->getVPNConfig()->getName(), vpn_item->getAccessibleResources());
	reinitialize();
}

void AccessibleResourceDialog::openAccessibleResource()
{
	const AccessibleResource resource = buttonResourceMaps.value(QObject::sender());

	QString program = resource.getProgram();
#ifdef _WIN32
	if (!program.isEmpty()) {
		program = program.replace(QLatin1String("%SYSTEMROOT%"), getSpecialFolderLocation(CSIDL_WINDOWS));
		program = program.replace(QLatin1String("%SYSTEM%"), getSpecialFolderLocation(CSIDL_SYSTEM));
		program = program.replace(QLatin1String("%PROGRAMFILES%"), getSpecialFolderLocation(CSIDL_PROGRAM_FILES));
		program = program.replace(QLatin1String("%PROGRAM FILES%"), getSpecialFolderLocation(CSIDL_PROGRAM_FILES));
	}
#endif

	bool success = false;
	if (program.isEmpty()) {
		success = QDesktopServices::openUrl(QUrl(resource.getUri()));
	} else {
		/* 网络共享参数处理, /字符 替换为 \字符 */
		QString params = resource.getUri();
		if (program.contains(QLatin1String("explorer"), Qt::CaseInsensitive)) {
			if (params.startsWith(QLatin1String("//")))
				params = params.replace(QLatin1String("/"), QLatin1String("\\"));
		}

		success = QProcess::startDetached(program, QStringList() << params);
	}

	if (!success) {
		const QString message = tr("Open resource %1\n%2 %3 fail").arg(resource.getName()).arg(program).arg(resource.getUri());
		MessageBoxUtil::error(this, tr("Open resource"), message);
	}
}

#ifdef _WIN32
QString AccessibleResourceDialog::getSpecialFolderLocation(int type)
{
	LPMALLOC pShellMalloc;
	wchar_t w_path[MAX_PATH + 1];
	QString q_path;

	if (SUCCEEDED(SHGetMalloc(&pShellMalloc))) {
		LPITEMIDLIST pidl;
		if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, type, &pidl))) {
			if (SHGetPathFromIDListW(pidl, w_path)) 
				q_path = QString::fromWCharArray(w_path);
			pShellMalloc->Free(pidl);
		}
	}

	pShellMalloc->Release();
	return q_path;
}
#endif
