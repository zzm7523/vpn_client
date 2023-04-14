#include <QApplication>
#include <QThread>
#include <QRegularExpression>
#include <QMutableListIterator>
#include <QDir>
#include <QDateTime>
#include <QTemporaryDir>
#include <QEventLoop>
#include <QByteArray>
#include <QDebug>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkAccessManager>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "../common/common.h"
#include "../common/file_util.h"
#include "../common/process_util.h"
#include "../common/system_info.h"
#include "../common/x509_certificate_util.h"
#include "../common/translate.h"
#include "../common/locator.h"
#include "../common/vpn_i_proxy.h"
#include "../common/request_dispatcher.h"

#include "../policy/policy.h"
#include "../policy/terminal_bind_policy.h"
#include "../policy/update_policy.h"
#include "../policy/password_policy.h"
#include "../policy/resource_policy.h"
#include "../policy/cluster_policy.h"
#include "../policy/policy_engine_i_proxy.h"
#include "../policy/policy_engine_servant.h"

#include "qtservice.h"
#include "vpn_log_parser.h"
#include "vpn_agent_servant.h"

#define VPN_EDGE_MAGIC       "^!#1Fx@&%xd?qR"

static Context gLastConnectCtx;

quint32 VPNAgentServant::nextExitEventId = 0;

VPNAgentServant::VPNAgentServant(const QString& uniqueIdentify)
	: VPNAgentSkeleton(uniqueIdentify), state(VPNAgentI::ReadyToConnect), error(VPNAgentI::NoError),
		requestCancel(false), initializationSequenceCompleted(false), logFile(NULL),
		vpnProcess(NULL), vpnProcessId(0), frontEngineProxy(NULL), backPolicyEngineI(NULL), inputAgentProxy(NULL)
{
	exitEventName = QString(QLatin1String(VPN_PROCESS)).remove(QLatin1String(".exe"), Qt::CaseInsensitive);
	exitEventName = QString(QLatin1String("%1_exit_%2")).arg(exitEventName).arg(++nextExitEventId);
}

bool VPNAgentServant::initialize(const QString& configDirectory, const QString& workingDirectory, const Context& ctx)
{
	Q_UNUSED(ctx)

	this->configDirectory = configDirectory;
	this->workingDirectory = workingDirectory;

	const QString edgeFile(QDir(this->configDirectory).absoluteFilePath(QLatin1String(VPN_EDGE_FILE)));
	readVPNEdge(edgeFile);

	// 注册安全策略引擎
	if (!backPolicyEngineI) {
		const QString backPolicyEngineIdentify = QString(QLatin1String("%1:BackPolicyEngineI")).arg(uniqueIdentify);
		backPolicyEngineI = new PolicyEngineServant(backPolicyEngineIdentify, false, this, NULL);
		RequestDispatcher::registerServant(QLatin1String("PolicyEngineI"), (PolicyEngineServant*) backPolicyEngineI);
	}

	return true;
}

void VPNAgentServant::clear(const Context& ctx)
{
	Q_UNUSED(ctx)
}

bool VPNAgentServant::registerPolicyEngine(const QHostAddress& hostAddress, quint16 port, const QString& engineUniqueIdentify,
		const Context& ctx)
{
	Q_UNUSED(ctx)

	unregisterPolicyEngine(Context::getDefaultContext());	// 只能有一个策略代理, 注销原有的注册

	frontEngineProxy = Locator::locate<PolicyEngineProxy>(hostAddress, port, engineUniqueIdentify);
	if (frontEngineProxy) {
		((PolicyEngineServant*) backPolicyEngineI)->setRemotePolicyEngine(frontEngineProxy);
		QObject::connect(frontEngineProxy, SIGNAL(disconnected()), this, SLOT(onPolicyEngineDisconnected()));
		return true;
	} else {
		qDebug() << "locate PolicyEngineProxy fail, host=" << hostAddress << ", port=" << port << ", uniqueIdentify="
			<< engineUniqueIdentify;
		return false;
	}
}

void VPNAgentServant::unregisterPolicyEngine(const Context& ctx)
{
	Q_UNUSED(ctx)

	if (frontEngineProxy) {
		frontEngineProxy->deleteLater();
		frontEngineProxy = NULL;
	}
}

bool VPNAgentServant::registerObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx)
{
	QMutableListIterator<VPNObserverProxy*> it(this->observerProxys);
	VPNObserverProxy *observerProxy = NULL;

	// 清理无效的观察者
	while (it.hasNext()) {
		observerProxy = it.next();
		if (observerProxy) {
			if (!observerProxy->isValid()) {
				observerProxy->deleteLater();
				it.remove();
			}
		}
	}

	unregisterObserver(hostAddress, port, observerUniqueIdentify, ctx);

	observerProxy = Locator::locate<VPNObserverProxy>(hostAddress, port, observerUniqueIdentify);
	if (observerProxy) {
		QObject::connect(observerProxy, SIGNAL(disconnected()), this, SLOT(onObserverDisconnected()));
		this->observerProxys.append(observerProxy);

		// 通知当前状态, ...
		notify_2(Q_ARG(VPNAgentI::State, this->state), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
		notify_1(Q_ARG(VPNEdge, this->edge), this->connectCtx);
		return true;
	} else {
		qDebug() << "locate VPNObserverProxy fail, host=" << hostAddress << ", port=" << port << ", uniqueIdentify="
			<< observerUniqueIdentify;
		return false;
	}
}

void VPNAgentServant::unregisterObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx)
{
	Q_UNUSED(ctx)

	QMutableListIterator<VPNObserverProxy*> it(this->observerProxys);
	VPNObserverProxy *observerProxy = NULL;
	TcpConnection *connection = NULL;

	while (it.hasNext()) {
		if ((observerProxy = it.next())) {
			connection = observerProxy->getConnection();
			if (!observerProxy->isValid() || (observerProxy->getUniqueIdentify() == observerUniqueIdentify &&
					connection->peerAddress() == hostAddress && connection->peerPort() == port)) {
				QObject::disconnect(observerProxy, SIGNAL(disconnected()), 0, 0);
				observerProxy->deleteLater();
				it.remove();
			}
		}
	}
}

bool VPNAgentServant::registerInputAgent(const QHostAddress& hostAddress, quint16 port, const QString& inputAgentUniqueIdentify,
		const Context& ctx)
{
	Q_UNUSED(ctx)

	unregisterInputAgent(Context::getDefaultContext());	// 只能有一个输入代理, 注销原有的注册

	inputAgentProxy = Locator::locate<VPNInputAgentProxy>(hostAddress, port, inputAgentUniqueIdentify);
	if (inputAgentProxy) {
		QObject::connect(inputAgentProxy, SIGNAL(disconnected()), this, SLOT(onInputAgentDisconnected()));
		return true;
	} else {
		qDebug() << "locate VPNInputAgentProxy fail, host=" << hostAddress << ", port=" << port << ", uniqueIdentify="
			<< inputAgentUniqueIdentify;
		return false;
	}
}

void VPNAgentServant::unregisterInputAgent(const Context& ctx)
{
	Q_UNUSED(ctx)

	if (inputAgentProxy) {
		inputAgentProxy->deleteLater();
		inputAgentProxy = NULL;
	}
}

void VPNAgentServant::connect(const ServerEndpoint& remote, const QStringList& params, const Context& ctx)
{
	Q_ASSERT(inputAgentProxy && backPolicyEngineI && observerProxys.size() > 0); // 要求存在输入代理,策略引擎,观察者代理

	// 总是断开前一次连接
	if (this->vpnProcess) {
		// 防止terminateVPN(...)调用终止OpenVPN进程时, 回调onProcessFinished(...)
		QObject::disconnect(vpnProcess, SIGNAL(finished(int, QProcess::ExitStatus)), 0, 0);
		QObject::disconnect(vpnProcess, SIGNAL(errorOccurred(QProcess::ProcessError)), 0, 0);
	}
	terminateVPN();
	QApplication::processEvents();

	// 总是清理缓存信息
	this->baseStats.clear();
	this->currStats.clear();
	this->tunnel.clear();
	this->accessibleResources.clear();
	this->logBuffer.clear();
//	this->edge.clear();	// 跨连接信息, 不要清理

	this->connectCtx = ctx;	// 记住当前连接上下文
	gLastConnectCtx = ctx;  // 记住最后连接上下文

	this->state = VPNAgentI::Connecting;	// 开始处理当前连接请求
	this->error = VPNAgentI::NoError;
	this->errorReason.clear();
	this->requestCancel = false;
	this->initializationSequenceCompleted = false;

	this->tunnel.setServerEndpoint(remote);	// 记住当前连接的服务端
	this->vpnProcessId = 0;
	this->vpnProcess = new QProcess();	// 每次连接都新建一个QProcess对象, 防止前一次连接输入输出干扰	

	QObject::connect(vpnProcess, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));
	QObject::connect(vpnProcess, SIGNAL(finished(int, QProcess::ExitStatus)), this,
		SLOT(onProcessFinished(int, QProcess::ExitStatus)));
	QObject::connect(vpnProcess, SIGNAL(readyReadStandardOutput()), this, SLOT(onProcessOutput()));
	QObject::connect(vpnProcess, SIGNAL(readyReadStandardError()), this, SLOT(onProcessOutput()));

	// 通知观察者正在建立连接
	Q_ASSERT(this->state == VPNAgentI::Connecting);
	notify_2(Q_ARG(VPNAgentI::State, this->state), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);

	qDebug() << "application dir path is " << QCoreApplication::applicationDirPath();
	if (workingDirectory.isEmpty()) {
		QTemporaryDir tempDir;
		tempDir.setAutoRemove(false);
		workingDirectory = tempDir.path();
	}
	qDebug() << "set OpenVPN process working directory to :" << workingDirectory;
	vpnProcess->setWorkingDirectory(workingDirectory);

	const QString program = QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QLatin1String(VPN_PROCESS));
	if (!QFile::exists(program)) {
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
		notify_2(Q_ARG(VPNAgentI::Error, (this->error = VPNAgentI::OtherError)),
			Q_ARG(QString, QLatin1String(VPN_PROCESS) + QLatin1String(" ") + QApplication::translate("VPNAgentI", "don't found!")),
			this->connectCtx);
		qDebug() << program << "don't found!";
	} else {
		this->logFile = openLogFile(workingDirectory, QLatin1String(VPN_LOG_FILE));
		if (this->logFile) {
			const QStringList arguments = generateVPNArguments(remote, params);
			qDebug() << "Open Connection.\n" << program + QLatin1String(" ") + arguments.join(QLatin1String(" "));
			vpnProcess->start(program, arguments);
			if (!vpnProcess->waitForStarted()) {
				const QString errorString = vpnProcess->errorString();
				notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
				notify_2(Q_ARG(VPNAgentI::Error, (this->error = VPNAgentI::OtherError)), Q_ARG(QString, errorString), this->connectCtx);
				qDebug() << VPN_PROCESS << " start fail!\n" << errorString;
			} else
				this->vpnProcessId = vpnProcess->processId();
		}
	}
}

void VPNAgentServant::disconnect(const Context& ctx)
{
	Q_UNUSED(ctx)

	if (this->state == VPNAgentI::Connecting || this->state == VPNAgentI::Connected || this->state == VPNAgentI::Reconnecting) {
#ifdef _DEBUG
		QThread::msleep(__MIN__(2000, __MAX__(200, rand() % 1000)));	// 模拟网络延时
#endif
		// 用户主动断开连接
		this->requestCancel = true;
		terminateVPN(false);
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
	}
}

QFile* VPNAgentServant::openLogFile(const QString& workDir, const QString& logFileName)
{
	const QString logFilePath = QDir(workDir).absoluteFilePath(logFileName);
#ifdef _WIN32
	FileUtil::setReadonlyAttribute(logFilePath, false);
#endif
	QFile *logFile = new QFile(logFilePath);	// 每次连接都新建一个QFile对象
	bool success = true, trunc = true;

	if (this->connectCtx.hasAttribute(Context::TRUNC_VPN_LOG))
		trunc = this->connectCtx.getAttribute(Context::TRUNC_VPN_LOG).toBool();

	if (trunc) {
		backupLogFile(workDir, logFileName);	// 备份日志文件
		success = logFile->open(QIODevice::WriteOnly | QIODevice::Truncate);
	} else {
		success = logFile->open(QIODevice::WriteOnly | QIODevice::Append);
	}

	if (success) {
#ifndef _WIN32
		FileUtil::addPermissions(logFilePath, FileUtil::ANY_BODY_READ);
#endif
		return logFile;
	} else {
		const QString errorString = logFile->errorString();
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
		notify_2(Q_ARG(VPNAgentI::Error, (this->error = VPNAgentI::OtherError)), Q_ARG(QString, errorString), this->connectCtx);
		logFile->close();
		return NULL;
	}
}

#define MAX_LOG_RETAIN_TIME		7

void VPNAgentServant::backupLogFile(const QString& backupDir, const QString& logFileName)
{
	const QDateTime currentDateTime = QDateTime::currentDateTime();
	const QDateTime expiredDateTime = currentDateTime.addDays(MAX_LOG_RETAIN_TIME * -1);
	QFile currLogFile(QDir(workingDirectory).absoluteFilePath(logFileName));

	// 备份当前日志
	if (currLogFile.exists() && currLogFile.size() > 0) {
		const QString backupFileName = QString(QLatin1String("%1.%2"))
			.arg(logFileName).arg(QString::number(currentDateTime.toTime_t()));
		if (!currLogFile.copy(QDir(backupDir).absoluteFilePath(backupFileName)))
			qDebug() << QLatin1String("backup current log file fail!");

	}

	// 删除过期的备份
	QListIterator<QFileInfo> it(QDir(backupDir).entryInfoList(QDir::Files, QDir::NoSort));
	while (it.hasNext()) {
		const QFileInfo& fileInfo = it.next();
		const QString& fileName = fileInfo.fileName();
		const QDateTime& created = fileInfo.created();

		if (fileName.startsWith(logFileName, Qt::CaseInsensitive) && created < expiredDateTime) {
			if (fileName.compare(logFileName, Qt::CaseInsensitive) != 0)
				QFile(fileInfo.absoluteFilePath()).remove();
		}
	}
}

void VPNAgentServant::readVPNEdge(const QString& edgeFileName)
{
	QFile edgeFile(edgeFileName);
	VPNEdge localEdge;

	if (edgeFile.open(QIODevice::Text | QIODevice::ReadOnly)) {
		QDataStream in(&edgeFile);
		in.setVersion(QDataStream::Qt_5_2);

		QString magic;
		in >> magic;
		if (magic == QLatin1String(VPN_EDGE_MAGIC))
			in >> localEdge;
		edgeFile.close();
	}

	this->edge = localEdge;
}

void VPNAgentServant::saveVPNEdge(const QString& edgeFileName)
{
#ifdef _WIN32
	FileUtil::setReadonlyAttribute(edgeFileName, false);
#endif
	QFile edgeFile(edgeFileName);

	if (edgeFile.open(QIODevice::Text | QIODevice::WriteOnly)) {
		QDataStream out(&edgeFile);
		out.setVersion(QDataStream::Qt_5_2);

		out << QString(QLatin1String(VPN_EDGE_MAGIC)) << this->edge;
		edgeFile.flush();
		edgeFile.close();
	}

#ifndef _WIN32
	FileUtil::addPermissions(edgeFileName, FileUtil::ANY_BODY_READ);
#endif
}

void VPNAgentServant::terminateVPN(bool silent, int waitTimeout)
{
	if ((state != VPNAgentI::Connecting && state != VPNAgentI::Connected && state != VPNAgentI::Reconnecting)
			|| !vpnProcess)
		return;

	state = VPNAgentI::Disconnecting; // 正在退出, 防止重入terminateVPN()

	// 通知观察者正在断开连接
	if (!silent) {
		Q_ASSERT(this->state == VPNAgentI::Disconnecting);
		notify_2(Q_ARG(VPNAgentI::State, this->state), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
	}

	// 关闭统计定时器
	QObject::disconnect(&statsTimer, 0, 0, 0);
	statsTimer.stop();

	if (vpnProcess) {
		QObject::disconnect(vpnProcess, SIGNAL(errorOccurred(QProcess::ProcessError)), 0, 0);
		QObject::disconnect(vpnProcess, SIGNAL(finished(int, QProcess::ExitStatus)), 0, 0);

		if (initializationSequenceCompleted)	// 应用VPN连接断开前安全策略
			applyPolicy(PolicyEngineI::DisconnectBefore);
	}

	// 等候openvpn进程退出
	if (waitTimeout > 0 && vpnProcess && vpnProcess->state() != QProcess::NotRunning) {
#ifdef _WIN32
		const QByteArray bytes = exitEventName.toLocal8Bit();
		HANDLE exitEvent = CreateEventA(NULL, TRUE, FALSE, bytes.constData());
#endif

		do {
			QApplication::processEvents();
#ifdef _WIN32
			if (exitEvent)
				SetEvent(exitEvent);
#endif
			if (vpnProcess) {
				vpnProcess->write("\n");	// VPN可能等候输入不响应退出事件
				vpnProcess->waitForBytesWritten(-1);	// 等候内容完整写出
			}

			if (waitTimeout <= 0 || !vpnProcess || vpnProcess->waitForFinished(500))
				break;

		} while ((waitTimeout -= 500) > 0);

#ifdef _WIN32
		if (exitEvent) {
			ResetEvent(exitEvent);
			CloseHandle(exitEvent);
		}
#endif
	}

	if (vpnProcess && vpnProcess->state() != QProcess::NotRunning) {	// 强制退出
		if (vpnProcessId)
			ProcessUtil::killProcess(vpnProcessId); 
		else
			vpnProcess->kill();
		vpnProcess->waitForFinished(2000);
	}
	QApplication::processEvents();

	if (vpnProcess) {
		// 不删除临时目录, 客户端可以查看日志
		vpnProcess->setWorkingDirectory(QCoreApplication::applicationDirPath());
		QObject::disconnect(vpnProcess, 0, 0, 0);
		vpnProcess->deleteLater();
		vpnProcess = NULL;
	}

	if (logFile) {
		if (logFile->isOpen())	// 关闭日志文件, 必须在openvpn进程退出后
			logFile->close();
		logFile->deleteLater();
		logFile = NULL;
	}

	if (initializationSequenceCompleted)	// 应用VPN连接断开后安全策略
		applyPolicy(PolicyEngineI::DisconnectAfter);

	if (backPolicyEngineI)
		backPolicyEngineI->clear(Context::getDefaultContext());	// 清理未处理的策略

	initializationSequenceCompleted = false;
}

void VPNAgentServant::writeToVPNProcess(const QString& description, const QString& input)
{
	const QString content = input.trimmed();
#if defined(_DEBUG)
	if (content.isEmpty()) {
		qDebug() << description << " writeToVPNProcess(...) empty string to vpn process";
	} else {
		if (content.compare(input, Qt::CaseSensitive) != 0)
			qDebug() << description << " input contain white space";
		if (content.compare(USER_CANCEL_INPUT, Qt::CaseSensitive) == 0) 
			qDebug() << description << " writeToVPNProcess(...) user cancel input";
		else
			qDebug() << description << " writeToVPNProcess(...) " << content;
	}
#else
	Q_UNUSED(description)
#endif

	if (vpnProcess && vpnProcess->state() == QProcess::Running && vpnProcess->isWritable()) {
		QByteArray bytes;
		bytes.append(input.toUtf8()).append('\n');
		vpnProcess->write(bytes);
		vpnProcess->waitForBytesWritten(-1);	// 等候内容完整写出
	}
}

void VPNAgentServant::onUpdateStatistics()
{
	// 只要隧道没有断开, 就一直发送统计信息; 隧道详细信息界面依赖它驱动更新
	if (state == VPNAgentI::Connected /* && !currStats.isEmpty()*/) {
#ifdef _WIN32
		currStats.updateByteCount(tunnel.getTunDeviceIndex(), QDateTime::currentDateTime(), baseStats);
#else
		currStats.updateByteCount(tunnel.getTunDeviceName(), QDateTime::currentDateTime(), baseStats);
#endif
		notify_1(Q_ARG(VPNStatistics, currStats), this->connectCtx);
	}
}

QStringList VPNAgentServant::generateVPNArguments(const ServerEndpoint& remote, const QStringList& params)
{
	bool explicitExitNotifyDefined = false;
	bool connectRetryMaxDefined = false;
	bool routeDelayDefined = false;

	QStringList arguments;

	arguments << QLatin1String("--remote") << remote.getHost() << QString::number(remote.getPort())
		<< ServerEndpoint::protocol2String(remote.getProtocol()).toLower();

	arguments << QLatin1String("--config") << QDir(configDirectory).absoluteFilePath(QLatin1String(VPN_CONFIG_FILE));
	arguments << QLatin1String("--integration");
#ifdef _WIN32
	arguments << QLatin1String("--service") << exitEventName;
#endif

	arguments.append(params);

	QFile advConfigFile(QDir(configDirectory).absoluteFilePath(QLatin1String(VPN_ADV_CONFIG_FILE)));
	if (advConfigFile.open(QIODevice::Text | QIODevice::ReadOnly)) {
		QTextStream in(&advConfigFile);
		in.setCodec("UTF-8"); // 配置文件采用UTF-8编码

		while (!in.atEnd()) {
			const QString line = in.readLine().trimmed();
			// 忽略空白行和注解
			if (line.startsWith(QLatin1Char('#')) || line.startsWith(QLatin1Char(';')))
				continue;

			QStringList parts = line.split(QRegularExpression(QLatin1String("\\s+")), QString::SkipEmptyParts);
			if (parts.size() == 0)
				continue;

			if (parts[0] == QLatin1String("explicit-exit-notify"))
				explicitExitNotifyDefined = true;
			else if (parts[0] == QLatin1String("connect-retry-max"))
				connectRetryMaxDefined = true;
			else if (parts[0] == QLatin1String("route-delay"))
				routeDelayDefined = true;
				
			arguments << QLatin1String("--") + parts[0];
			for (int i = 1; i < parts.size(); ++i)
				arguments << parts[i];
		}
		advConfigFile.close();
	}

	if (ServerEndpoint::Udp == remote.getProtocol()) {
		if (!explicitExitNotifyDefined)
			arguments << QLatin1String("--explicit-exit-notify") << QString::number(2);
	} else {
		if (!connectRetryMaxDefined)
			arguments << QLatin1String("--connect-retry-max") << QString::number(1);
	}

	if (!routeDelayDefined)
		arguments << QLatin1String("--route-delay") << QString::number(2);

	return arguments;
}

bool VPNAgentServant::applyPolicy(PolicyEngineI::ApplyPoint point)
{
	ApplyResult result(ApplyResult::Success);

	// Context::VPN_TUNNEL比较大, 复制一个本地上下文, 不要放全局上下文
	Context localCtx(this->connectCtx);
	localCtx.setAttribute(Context::POLICY_ENGINE_COUNTER, QVariant::fromValue(0));
	localCtx.setAttribute(Context::VPN_TUNNEL, QVariant::fromValue(tunnel));

	while (backPolicyEngineI->hasPolicy(point, localCtx)) {
		try {
			result = backPolicyEngineI->applyPolicy(point, localCtx);
		} catch (const SocketException& ex) {
			// 忽略SocketException异常, 客户端可能异常终止
			result.setResult(ApplyResult::Fail);
			qDebug() << "VPNAgentServant::applyPolicy(...), " << ex.getMessage();
		}

		if (ApplyResult::Success == result.getResult()) {
			const QString typeName = result.getAttribute(ApplyResult::TYPE_NAME).toString();
			if (typeName == PasswordPolicy::type_name()) {
				const QString passwordService = result.getAttribute(ApplyResult::SERVICE_URL).toString();
				bool weakPassword = result.getAttribute(ApplyResult::WEAK_PASSWORD).toBool();
				edge.setPasswordService(passwordService);
				edge.setWeakPassword(weakPassword);
			} else if (typeName == UpdatePolicy::type_name()) {
				const QString updateService = result.getAttribute(ApplyResult::SERVICE_URL).toString();
				edge.setUpdateService(updateService);
			} else if (typeName == ResourcePolicy::type_name()) {
				const AccessibleResource resource = result.getAttribute(ApplyResult::ACCESSIBLE_RESOURCE).value<AccessibleResource>();
				accessibleResources.append(resource);
			} else if (typeName == ClusterPolicy::type_name()) {
				int algorithm = result.getAttribute(ApplyResult::CLUSTER_ALGORITHM).value<int>();
				edge.setClusterAlgorithm(static_cast<ServerEndpointSelector::Algorithm>(algorithm));
				const QList<ServerEndpoint> endpoints = result.getAttribute(ApplyResult::SERVER_ENDPOINT_LIST).value<QList<ServerEndpoint>>();
				for (int i = 0; i < endpoints.size(); ++i)
					edge.addClusterEndpoint(endpoints.at(i));
			}

		} else if (ApplyResult::Warning == result.getResult()) {
			notify_2(Q_ARG(VPNAgentI::Warning, VPNAgentI::PolicyWarning), Q_ARG(QString, result.getReason()), localCtx);

		} else if (ApplyResult::Fail == result.getResult()) {
			if (PolicyEngineI::DisconnectAfter != point) {
				terminateVPN();	// 策略执行失败, 主动断开隧道
				notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), localCtx);
				break;
			}
		}
	}

	return ApplyResult::Fail == result.getResult() ? false : true; 
}

void VPNAgentServant::handleOpenVPNProgress(VPNLogParser& parser)
{
	if (VPNAgentI::Connecting != state && VPNAgentI::Reconnecting != state && VPNAgentI::Disconnecting != state)
		return;

	QString progressDetail;

	if (parser.requestOpenEncryptDevices()) {
		progressDetail = QApplication::translate("VPNAgentI", "Open encrypt device ...");
	} else if (parser.requestResolveHost()) {
		progressDetail = QApplication::translate("VPNAgentI", "Resolving host name ...");
	} else if (parser.requestConnectServer()) {
		progressDetail = QApplication::translate("VPNAgentI", "Waiting for server reply ...");
	} else if (parser.requestClientConfig()) {
		progressDetail = QApplication::translate("VPNAgentI", "Get user config ...");
	} else if (parser.requestAssignIPAddress()) {
		progressDetail = QApplication::translate("VPNAgentI", "Assign ip address ...");
	} else if (parser.requestAddRoutes()) {
		progressDetail = QApplication::translate("VPNAgentI", "Add routes ...");
	}

	if (!progressDetail.isEmpty()) {
		notify_1(Q_ARG(QString, progressDetail), this->connectCtx);
	}
}

void VPNAgentServant::handleOpenVPNError(VPNLogParser& parser)
{
	bool alwaysNotify = false;	// 总是通知前端发生了错误
	Context localCtx(this->connectCtx);
	VPNAgentI::Error prevError = this->error;
	QString prevErrorReason = this->errorReason;

	if (parser.hasTLSStartHelloFailed()) {
		error = VPNAgentI::ConnectionError;
		errorReason = QApplication::translate("VPNAgentI", "TLS start hello failed, check your network connectivity");
	} else if (parser.hasTLSKeyNegotiateFailed()) {
		error = VPNAgentI::TLSError;
		errorReason = QApplication::translate("VPNAgentI", "TLS key negotiate failed, check your network connectivity");
	} else if (parser.hasTunnelNegotiateError()) {
		error = VPNAgentI::OtherError;
		errorReason = QApplication::translate("VPNAgentI", "Failed to negotiate tunnel parameters");
	} else if (parser.hasCannotResolveHostAddress()) {
		error = VPNAgentI::ConnectionError;
		errorReason = QApplication::translate("VPNAgentI", "Cannot resolve host address! See log for details");
	} else if (parser.hasConnectionError()) {
		error = VPNAgentI::ConnectionError;
		errorReason = QApplication::translate("VPNAgentI", "VPN connection failed! check your network connectivity");
	} else if (parser.hasTLSAuthError()) {
		error = VPNAgentI::TLSAuthError;
		errorReason = QApplication::translate("VPNAgentI", "cannot locate HMAC in incoming packet");
	} else if (parser.hasPrivateKeyPasswordVerifyError()) {
		int retryCount = 0;
		alwaysNotify = true;
		error = VPNAgentI::PINError;
		errorReason = QApplication::translate("VPNAgentI", "Private Key Password verify fail");
		if (parser.getRetryCount(&retryCount)) {
			errorReason += QLatin1String(", ");
			if (retryCount <= 0)
				errorReason += QApplication::translate("VPNAgentI", "Encrypt device locked");
			else
				errorReason += (QApplication::translate("VPNAgentI", "residual try count")  + QLatin1Char(' ')
					+ QString::number(retryCount));
		}
		localCtx.setAttribute(Context::PIN_ERROR, QVariant::fromValue(errorReason));

	} else if (parser.hasUnableGetIssuerCert()) {
		alwaysNotify = true;
		error = VPNAgentI::CertError;
		errorReason = QApplication::translate("VPNAgentI", "Unable to get issuer certificate");
	} else if (parser.hasCannotLoadCertificate()) {
		alwaysNotify = true;
		error = VPNAgentI::CertError;
		errorReason = QApplication::translate("VPNAgentI", "Cannot load client certificate");
	} else if (parser.hasClientCertificateRevoked()) {
		alwaysNotify = true;
		error = VPNAgentI::CertError;
		errorReason = QApplication::translate("VPNAgentI", "Client certificate revoked");
	} else if (parser.hasClientCertificateExpired()) {
		alwaysNotify = true;
		error = VPNAgentI::CertError;
		errorReason = QApplication::translate("VPNAgentI", "Client certificate expired");
	} else if (parser.hasClientCertificateIsNotYetValid()) {
		alwaysNotify = true;
		error = VPNAgentI::CertError;
		errorReason = QApplication::translate("VPNAgentI", "Client certificate is not yet valid");

	} else if (parser.hasProxyAuthError()) {
		alwaysNotify = true;
		error = VPNAgentI::ProxyAuthError;
		errorReason = QApplication::translate("VPNAgentI", "Proxy authenticate fail");
		localCtx.setAttribute(Context::PROXY_AUTH_ERROR, QVariant::fromValue(errorReason));

	} else if (parser.hasAuthError()) {
		alwaysNotify = true;
		error = VPNAgentI::AuthError;
		if (parser.getAuthErrorReason(errorReason)) {
			// TODO, 要求终端绑定		
//			localCtx.setAttribute(Context::TERMINAL_BIND, QVariant::fromValue(true));
		} else
			errorReason = QApplication::translate("VPNAgentI", "User authenticate fail");
		localCtx.setAttribute(Context::AUTH_ERROR, QVariant::fromValue(errorReason));
		// 自动探测是否启用密码认证需要立即断开, 并且state置为VPNAgentI::Disconnected
		terminateVPN(true, 0);	// 连接未成功, OpenVPN没有需要清理的资源; 等候超时置0, 立即终止OpenVPN进程
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), localCtx);

	} else if (parser.hasNeedPEMpass()) {
		error = VPNAgentI::PINError;
		errorReason = QApplication::translate("VPNAgentI", "TLS Error! Need PEM pass phrase for private key");
	} else if (parser.hasUnknownCA()) {
		error = VPNAgentI::CertError;
		errorReason = QApplication::translate("VPNAgentI", "TLS error! TLS alert unknown ca");
	} else if (parser.hasTLSError()) {
		if (prevError == VPNAgentI::NoError) {	// 不要覆盖其它错误
			error = VPNAgentI::TLSError;
			errorReason = QApplication::translate("VPNAgentI", "TLS error! See log for details");
		}
	} else if (parser.hasDecryptError()) {
		error = VPNAgentI::OtherError;
		errorReason = QApplication::translate("VPNAgentI", "EVP_DecryptFinal: bad decrypt");
	} else if (parser.hasMacVerifyFailure()) {
		error = VPNAgentI::OtherError;
		errorReason = QApplication::translate("VPNAgentI", "PKCS12_parse: mac verify failure");

	} else if (parser.hasAllTAPUsed()) {
		error = VPNAgentI::NotAvailableTAP;
		errorReason = QApplication::translate("VPNAgentI", "All TAP-Windows adapters on this system are currently in use");
	} else if (parser.hasNoTAP()) {
		error = VPNAgentI::NotAvailableTAP;
		errorReason = QApplication::translate("VPNAgentI", "There are no TAP-Windows adapters on this system");

	} else if (parser.hasUnsupportedCipher()) {
		QString unsupportedCipher;
		parser.getUnsupportedCipher(unsupportedCipher);
		error = VPNAgentI::ParameterError;
		errorReason = QApplication::translate("VPNAgentI", "Cipher %1 require hardware support").arg(unsupportedCipher);
	} else if (parser.hasUnsupportedAuth()) {
		QString unsupportedAuth;
		parser.getUnsupportedAuth(unsupportedAuth);
		error = VPNAgentI::ParameterError;
		errorReason = QApplication::translate("VPNAgentI", "Auth %1 require hardware support").arg(unsupportedAuth);

	} else if (parser.hasParameterError()) {
		error = VPNAgentI::ParameterError;
		errorReason = QApplication::translate("VPNAgentI", "VPN parameter error! See log for details");
	} else if (parser.hasSigTermReceived()) {
		if (prevError == VPNAgentI::NoError) {	// 不要覆盖其它错误
			error = VPNAgentI::OtherError;
			errorReason = QApplication::translate("VPNAgentI", "SIGTERM received! See log for details");
		}
	} else if (parser.hasFatalError()) {
		if (prevError == VPNAgentI::NoError) {	// 不要覆盖其它错误
			error = VPNAgentI::OtherError;
			errorReason = QApplication::translate("VPNAgentI", "Fatal error! See log for details");
		}
	}

	// 发生错误时, 不主动终止VPN进程, 通知控制端, 由控制端决定是否终止连接
	if (error != VPNAgentI::NoError && (alwaysNotify || error != prevError || errorReason != prevErrorReason)) {
		notify_2(Q_ARG(VPNAgentI::Error, error), Q_ARG(QString, errorReason), localCtx);	// 不要重复发送同样的错误消息
	}
}

bool VPNAgentServant::handleOpenVPNInput(VPNLogParser& parser)
{
	// !!onInputAgentDisconnected发生时, 设置this->inputAgentProxy = NULL; 保存本地变量
	VPNInputAgentProxy *inputAgentProxy = this->inputAgentProxy;
	Q_ASSERT(inputAgentProxy != NULL);
	// !!如果用户放弃连接, 必须写入USER_CANCEL_INPUT宏, 让OpenVPN事件循环继续, 能够响应退出事件	
	bool result = true;

	// 如果不处于连接状态或正在连接状态, 不需要进一步处理, 立即退出
	if (state != VPNAgentI::Connecting && state != VPNAgentI::Connected && state != VPNAgentI::Reconnecting)
		return result;

#ifdef _DEBUG
	QThread::msleep(__MIN__(2000, __MAX__(200, rand() % 1000)));	// 模拟网络延时
#endif

	if (parser.requestTrustServerCertificate()) {
		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
			const QString messagge(QApplication::translate("VPNAgentI", "Verify server certificate ..."));
			notify_1(Q_ARG(QString, messagge), this->connectCtx);
		}
		QStringList certChain;
		if (parser.getCertificateChain(certChain)) {
			VPNInputAgentI::TrustOption option = inputAgentProxy->trustServerCertificate(certChain, this->connectCtx);
			requestCancel = inputAgentProxy->isCanceled();
			if (!requestCancel)
				writeToVPNProcess(QLatin1String("server certificate chain"),
					VPNInputAgentI::Trust == option ? QLatin1String("trust") : QLatin1String("reject"));
			else
				writeToVPNProcess(QLatin1String("server certificate chain"), USER_CANCEL_INPUT);
		} else 
			result = false;

	} else if (parser.requestClientCertificate()) {
		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
			const QString messagge(QApplication::translate("VPNAgentI", "Authentication user identity ..."));
			notify_1(Q_ARG(QString, messagge), this->connectCtx);
		}
		QStringList keyTypes, issuers;
		if (parser.getTLSVersion(tunnel) && parser.getKeyTypes(keyTypes) && parser.getIssuers(issuers)) {
			const X509CertificateInfo certInfo =
				inputAgentProxy->chooseClientCertificate(tunnel.getTLSVersion(), keyTypes, issuers, this->connectCtx);
			requestCancel = inputAgentProxy->isCanceled();
			Q_ASSERT(requestCancel || !certInfo.isEmpty());

			if (!requestCancel) {
				const QString& source = certInfo.getSource();
				X509 *cert = certInfo.getCertificate();
				QString identity;

				/*
				if (QLatin1String(ENCRYPT_DEVICE_SOURCE) == source)
					identity = QLatin1String("gmedapicert ") + certInfo.getIdentity();
				else
				*/
					if (QLatin1String(PKCS12_FILE_SOURCE) == source) {
#ifdef ENABLE_GUOMI
					identity = QLatin1String("pkcs12 \"") + certInfo.getIdentity() + QLatin1String("\" \"") +
						certInfo.getIdentity() + QLatin1String("\"");
#else
					identity = QLatin1String("pkcs12 \"") + certInfo.getIdentity() + QLatin1String("\"");
#endif
				} else /* if (QLatin1String(MS_CRYPTAPI_SOURCE) == source) */ {
					// 不能用 cryptoapicert THUMB ..., 因为openvpn作为服务运行, 无法访问当前用户的CertStore
					identity = X509CertificateUtil::encode_to_base64(cert);	// 证书来自CertStore时必须输出完整证书
				}
				writeToVPNProcess(QLatin1String("client certificate"), identity);
			} else
				writeToVPNProcess(QLatin1String("client certificate"), USER_CANCEL_INPUT);
		} else
			result = false;

	} else if (parser.requestPrivateKeyPassword()) {
		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
			const QString messagge(QApplication::translate("VPNAgentI", "Authentication user identity ..."));
			notify_1(Q_ARG(QString, messagge), this->connectCtx);
		}
		const QByteArray keyPassword = inputAgentProxy->getPrivateKeyPassword(this->connectCtx);
		requestCancel = inputAgentProxy->isCanceled();
#ifdef STRONG_SECURITY_RESTRICTION
		Q_ASSERT(requestCancel || !keyPassword.isEmpty());
#endif
		if (!requestCancel)
			writeToVPNProcess(QLatin1String("private key password"), QString::fromLocal8Bit(keyPassword));
		else
			writeToVPNProcess(QLatin1String("private key password"), USER_CANCEL_INPUT);

	} else if (parser.requestPrivateKeyEncrypt()) {
		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
			const QString messagge(QApplication::translate("VPNAgentI", "Authentication user identity ..."));
			notify_1(Q_ARG(QString, messagge), this->connectCtx);
		}
		QString encryptRequest;
		if (parser.getPrivateKeyEncryptReqeust(encryptRequest)) {
			const QByteArray ciphertext = inputAgentProxy->getPrivateKeyEncrypt(encryptRequest, connectCtx);
			requestCancel = inputAgentProxy->isCanceled();
			if (!requestCancel && !ciphertext.isEmpty())
				writeToVPNProcess(QLatin1String("private key encrypt"), QLatin1String(ciphertext.toBase64()));
			else
				writeToVPNProcess(QLatin1String("private key encrypt"), USER_CANCEL_INPUT);
		} else
			result = false;

	} else if (parser.requestUsername()) {
		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
			const QString messagge(QApplication::translate("VPNAgentI", "Authentication user identity ..."));
			notify_1(Q_ARG(QString, messagge), this->connectCtx);
		}
		const QString userName = inputAgentProxy->getUserName(connectCtx);
		requestCancel = inputAgentProxy->isCanceled();
		Q_ASSERT(requestCancel || !userName.isEmpty());
		writeToVPNProcess(QLatin1String("user name"), requestCancel ? USER_CANCEL_INPUT : userName);

	} else if (parser.requestPassword()) {
//		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
//			const QString messagge(QApplication::translate("VPNAgentI", "Authentication user identity ..."));
//			notify_1(Q_ARG(QString, messagge), this->connectCtx);
//		}
		const QString password = inputAgentProxy->getPassword(connectCtx);
		requestCancel = inputAgentProxy->isCanceled();
#ifdef STRONG_SECURITY_RESTRICTION
		Q_ASSERT(requestCancel || !password.isEmpty());
#endif
		writeToVPNProcess(QLatin1String("password"), requestCancel ? USER_CANCEL_INPUT : password);

	} else if (parser.requestProxyUsername()) {
		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
			const QString messagge(QApplication::translate("VPNAgentI", "Authentication user identity ..."));
			notify_1(Q_ARG(QString, messagge), this->connectCtx);
		}
		const QString proxyUserName = inputAgentProxy->getProxyUserName(connectCtx);
		requestCancel = inputAgentProxy->isCanceled();
		Q_ASSERT(requestCancel || !proxyUserName.isEmpty());
		writeToVPNProcess(QLatin1String("proxy user name"), requestCancel ? USER_CANCEL_INPUT : proxyUserName);

	} else if (parser.requestProxyPassword()) {
//		if (VPNAgentI::Connecting == state || VPNAgentI::Reconnecting == state) {
//			const QString messagge(QApplication::translate("VPNAgentI", "Authentication user identity ..."));
//			notify_1(Q_ARG(QString, messagge), this->connectCtx);
//		}
		const QString proxyPassword = inputAgentProxy->getProxyPassword(this->connectCtx);
		requestCancel = inputAgentProxy->isCanceled();
#ifdef STRONG_SECURITY_RESTRICTION
		Q_ASSERT(requestCancel || !proxyPassword.isEmpty());
#endif
		writeToVPNProcess(QLatin1String("proxy password"), requestCancel ? USER_CANCEL_INPUT : proxyPassword);

	} else if (parser.requestPolicyResponse()) {
		if (applyPolicy(PolicyEngineI::ConnectedBefore))	// 应用连接建立前策略
			writeToVPNProcess(QLatin1String("request policy response"), QLatin1String("accept"));
		else
			writeToVPNProcess(QLatin1String("request policy response"), QLatin1String("reject"));
	}

	if (requestCancel) {
		terminateVPN();
		// 用户主动放弃连接, 发送VPNAgentI::ReadyToConnect状态
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::ReadyToConnect)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
	}
	return result;
}

bool VPNAgentServant::extractTunnelInfo(VPNLogParser& parser)
{
	if (parser.isOpenEncryptDevices()) {
		if (!parser.getOpenedEncryptDevices(this->tunnel))
			return false; // 输出不完整
	}

	if (parser.isTLSDetails()) {
		if (!parser.getTLSVersion(this->tunnel) || !parser.getTLSCipher(this->tunnel))
			return false;	// 输出不完整
	}
	
	if (parser.isCipher()) {
		if (!parser.getCipher(this->tunnel))
			return false;	// 输出不完整
	}

	if (parser.isAuth()) {
		if (!parser.getAuth(this->tunnel))
			return false;// 输出不完整
	}

	if (parser.isFragmentOption()) {
		if (!parser.getFragmentOption(this->tunnel))
			return false;// 输出不完整
	}

	if (parser.isCompressionOption()) {
		if (!parser.getCompressionOption(this->tunnel))
			return false;// 输出不完整
	}

	if (parser.isTunDeviceType()) {
		if (!parser.getTunDeviceType(this->tunnel))
			return false;// 输出不完整
	}

	if (parser.isTunDeviceName()) {
		if (!parser.getTunDeviceName(this->tunnel))
			return false;// 输出不完整
	}

#ifdef _WIN32
	if (parser.isTunDeviceIndex()) {
		if (!parser.getTunDeviceIndex(this->tunnel))
			return false;// 输出不完整
	}
#endif

	if (parser.isVirtualIPv4Gateway()) {
		if (!parser.getVirtualIPv4Gateway(this->tunnel))
			return false;	// 输出不完整
	}

	if (parser.isVirtualIPv4Addr()) {
		if (!parser.getVirtualIPv4Addr(this->tunnel))
			return false;	// 输出不完整
	}

	if (parser.isVirtualIPv6Addr()) {
		if (!parser.getVirtualIPv6Addr(this->tunnel))
			return false;	// 输出不完整
	}

	if (parser.isKeepAlive()) {
		if (!parser.getKeepAlive(this->tunnel))
			return false;	// 输出不完整
	}

	if (parser.isPolicy()) {
		QStringList policys;
		if (parser.getPolicys(policys)) {
			Q_FOREACH (QString policy, policys)
				this->backPolicyEngineI->addPolicy(policy, Context::getDefaultContext());
		}
		else
			return false;	// 输出不完整
	}

	return true;
}

void VPNAgentServant::deleteARP()
{
#ifdef _WIN32
	// 运行 arp -d * 命令
	// 不要用QProcess::startDetached(...), 它会显示控制台窗口
	ProcessUtil::start("arp", QStringList() << "-d" << "*", QString());
//	QProcess::startDetached("arp", QStringList() << "-d" << "*");
#endif
}

void VPNAgentServant::onProcessOutput()
{
	if (!this->logFile || !this->vpnProcess)
		return;

	QByteArray output = this->vpnProcess->readAllStandardOutput();
	if (output.isEmpty())
		output = this->vpnProcess->readAllStandardError();
	if (output.isEmpty())
		return;

	if (this->logFile && this->logFile->isOpen()) {	// 写输出到日志文件
		this->logFile->write(output);
#ifdef _DEBUG
		logFile->write("-------------------------------------------------------------------------\n");
#endif
		this->logFile->flush();
		// Qt's QFile.flush() only flushes the Qt/C buffers to the OS, it never calls fsync() to ensure
		// the OS has written the data to disk.
#ifdef _WIN32
		HANDLE fh = (HANDLE) _get_osfhandle(this->logFile->handle());
		FlushFileBuffers(fh);
#else
		fsync(this->logFile->handle());
#endif
	}

	if (!this->logBuffer.isEmpty()) {
		output.insert(0, this->logBuffer);	// 合并上次未处理完的日志
		this->logBuffer.clear();
	}

	if (VPNAgentI::Disconnecting == state || VPNAgentI::Disconnected == state)
		return;	// 不需要进一步处理

	// 不是所有的日志输出都带换行符, 例如: Enter Private Key Password:
//	Q_ASSERT(output.endsWith('\r') || output.endsWith('\n'));

	VPNLogParser parser(output);

	// 用户主动断开连接, 不需要处理错误
	if (!this->requestCancel)
		handleOpenVPNError(parser);	// 必须先处理错误

	if (parser.isRestarting()) {	// 跟踪重连(PING超时, 或SIGUSR1信号)
		// 不要清理错误
		this->initializationSequenceCompleted = false;
		this->tunnel.clear();
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Reconnecting)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
	}

	if (VPNAgentI::Connected != this->state)
		handleOpenVPNProgress(parser);	// 处理连接进度

	// 连接成功后, 一些隧道信息也可能会发生变化
	if (!extractTunnelInfo(parser))
		goto underflow;	// 输出不完整

	try {
		if (!handleOpenVPNInput(parser))	// 其次处理OpenVPN输入
			goto underflow; // 输出不完整
	} catch (const SocketException& ex) {
		// 忽略SocketException异常, 客户端可能异常终止
		qDebug() << "VPNAgentServant::handleOpenVPNInput(...), " << ex.getMessage();
	}

	if (parser.isInitializationSequenceCompleted()) {
		// 连接成功, 清理错误跟踪上下文信息
		this->connectCtx.removeAttribute(Context::TERMINAL_BIND);
		this->connectCtx.removeAttribute(Context::PIN_ERROR);
		this->connectCtx.removeAttribute(Context::AUTH_ERROR);
		this->connectCtx.removeAttribute(Context::PROXY_AUTH_ERROR);

		this->initializationSequenceCompleted = true;
		this->state = VPNAgentI::Connected;
		this->tunnel.setEstablishedTime(QDateTime::currentDateTime());
		applyPolicy(PolicyEngineI::ConnectedAfter);	// 应用连接建立后策略

#ifdef _DEBUG
		if (this->tunnel.getVirtualIPv4Addr().isEmpty() || this->tunnel.getTunDeviceName().isEmpty())
			qDebug() << "Virtual ipv4 or tun device name parse fail";
#endif
		if (this->state == VPNAgentI::Connected)
			notify_2(Q_ARG(VPNAgentI::State, this->state), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);

		notify_1(Q_ARG(VPNEdge, this->edge), this->connectCtx);	// !!更新状态为已连接后调用
		const QString edgeFile(QDir(configDirectory).absoluteFilePath(QLatin1String(VPN_EDGE_FILE)));
		saveVPNEdge(edgeFile);	// 保存VPNEdge

		notify_1(Q_ARG(QList<AccessibleResource>, this->accessibleResources), this->connectCtx);

#ifdef _WIN32
		baseStats.updateByteCount(this->tunnel.getTunDeviceIndex(), QDateTime::currentDateTime());
#else
		baseStats.updateByteCount(this->tunnel.getTunDeviceName(), QDateTime::currentDateTime());
#endif

		QObject::connect(&statsTimer, SIGNAL(timeout()), this, SLOT(onUpdateStatistics()));
		statsTimer.start(VPN_STATISTICS_INTERVAL);	// 启动统计定时器

		deleteARP();	// 清理arp缓存
	}

	Q_ASSERT(this->logBuffer.size() == 0);
	return;

underflow:
	this->logBuffer = output;	// 输出不完整; 缓存日志, 下一次合并处理
	Q_ASSERT(this->logBuffer.size() != 0);
	return;
}

void VPNAgentServant::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
	// TODO, 如果是OpenVPN进程崩溃, 调用崩溃诊断工具发送崩溃诊断报告
	Q_UNUSED(exitCode)
	Q_UNUSED(exitStatus)
	terminateVPN();
	notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
}

void VPNAgentServant::onProcessError(QProcess::ProcessError processError)
{
	QString errMessage = Translate::translateProcessError(processError);
	qDebug() << errMessage << "\n";
	notify_2(Q_ARG(VPNAgentI::Error, VPNAgentI::OtherError), Q_ARG(QString, errMessage), this->connectCtx);
}

void VPNAgentServant::onPolicyEngineDisconnected()
{
	if (frontEngineProxy)
		QObject::disconnect(frontEngineProxy, SIGNAL(disconnected()), 0, 0);

	// frontEngineProxy不要删除, 置NULL, 其它函数可能还依赖它
/*
	frontEngineProxy->deleteLater();
	frontEngineProxy = NULL;
*/

	bool haveActiveObserver = false;
	QListIterator<VPNObserverProxy*> it(this->observerProxys);
	while (haveActiveObserver && it.hasNext()) {
		if (it.next()->isValid())
			haveActiveObserver = true;
	}

	if (!haveActiveObserver) {
		terminateVPN();
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
	}
}

void VPNAgentServant::onInputAgentDisconnected()
{
	if (inputAgentProxy)
		QObject::disconnect(inputAgentProxy, SIGNAL(disconnected()), 0, 0);

	// inputAgentProxy不要删除, 置NULL, 其它函数可能还依赖它
/*
	inputAgentProxy->deleteLater();
	inputAgentProxy = NULL;
*/

	bool haveActiveObserver = false;
	QListIterator<VPNObserverProxy*> it(this->observerProxys);
	while (haveActiveObserver && it.hasNext()) {
		if (it.next()->isValid())
			haveActiveObserver = true;
	}

	if (!haveActiveObserver) {
		// 没有观察者, 终止连接, 不需要再发送通知
		terminateVPN();
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
	}
}

void VPNAgentServant::onObserverDisconnected()
{
	VPNObserverProxy *observer = dynamic_cast<VPNObserverProxy*>(QObject::sender());
	if (observer)
		QObject::disconnect(observer, SIGNAL(disconnected()), 0, 0);

	// 不要从observerProxys列表移除, 其它函数可能还在迭代observerProxys列表
/*
	this->observerProxys.removeAll(observer);
	observer->deleteLater();
*/

	bool haveActiveObserver = false;
	QListIterator<VPNObserverProxy*> it(this->observerProxys);
	while (haveActiveObserver && it.hasNext()) {
		if (it.next()->isValid())
			haveActiveObserver = true;
	}

	if (!haveActiveObserver && this->inputAgentProxy == NULL) {
		// 没有观察者, 终止连接, 不需要再发送通知
		terminateVPN();
		notify_2(Q_ARG(VPNAgentI::State, (this->state = VPNAgentI::Disconnected)), Q_ARG(VPNTunnel, this->tunnel), this->connectCtx);
	}
}

template <typename T>
void VPNAgentServant::notify_1(QArgument<T> t, const Context& ctx)
{
	QListIterator<VPNObserverProxy*> it(this->observerProxys);
	VPNObserverProxy *observerProxy;

	// 发送最后活动USER_IDENTIFY, SESSION_IDENTIFY给控制端
	Context localCtx(this->connectCtx);
	localCtx.setAttribute(Context::USER_IDENTIFY, gLastConnectCtx.getAttribute(Context::USER_IDENTIFY).toString());
	localCtx.setAttribute(Context::SESSION_IDENTIFY, gLastConnectCtx.getAttribute(Context::SESSION_IDENTIFY).toString());

	while (it.hasNext()) {
		if ((observerProxy = it.next())) {
			if (observerProxy->isValid()) {
				bool result = QMetaObject::invokeMethod(observerProxy, "notify", Qt::QueuedConnection,
					t, Q_ARG(Context, localCtx));
				Q_ASSERT_X(result, "notify_1", "QMetaObject::invokeMethod(...) fail");
//				observerProxy->notify(t, localCtx);
			} else {
				// 不要从observerProxys列表移除, 其它函数可能还在迭代observerProxys列表
			}
		}
	}
}

template <typename T1, typename T2>
void VPNAgentServant::notify_2(QArgument<T1> t1, QArgument<T2> t2, const Context& ctx)
{
	QListIterator<VPNObserverProxy*> it(this->observerProxys);
	VPNObserverProxy *observerProxy;

	// 发送最后活动USER_IDENTIFY, SESSION_IDENTIFY给控制端
	Context localCtx(this->connectCtx);
	localCtx.setAttribute(Context::USER_IDENTIFY, gLastConnectCtx.getAttribute(Context::USER_IDENTIFY).toString());
	localCtx.setAttribute(Context::SESSION_IDENTIFY, gLastConnectCtx.getAttribute(Context::SESSION_IDENTIFY).toString());

	while (it.hasNext()) {
		if ((observerProxy = it.next())) {
			if (observerProxy->isValid()) {
				bool result = QMetaObject::invokeMethod(observerProxy, "notify", Qt::QueuedConnection,
					t1, t2, Q_ARG(Context, localCtx));
				Q_ASSERT_X(result, "notify_2", "QMetaObject::invokeMethod(...) fail");
//				observerProxy->notify(t1, t2, localCtx);
			} else {
				// 不要从observerProxys列表移除, 其它函数可能还在迭代observerProxys列表
			}
		}
	}
}
