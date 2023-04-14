#if defined(_WIN32) || defined(WIN32)
#include <QEventLoop>
#include <QTimer>
#include <QFile>
#include <QDir>
#include <QDebug>
#include <QStringList>
#include <QCoreApplication>
#include <QRegularExpression>

#include "common.h"
#include "process_util.h"
#include "translate.h"

#include "tapdriver_manager.h"

TapDriverManagerPrivate::TapDriverManagerPrivate(const QString& _driverDir)
	: driverDir(_driverDir), drvAvailable(false), drvInstalledSuccess(false), drvCount(0),
	drvRemovedSuccess(false), drvEnableSuccess(false), drvDisableSuccess(false)
{
}

bool TapDriverManagerPrivate::probeTapDriverInf()
{
	const QStringList infos = QDir(driverDir).entryList(QDir::Files, QDir::Name);

	for (int i = 0; i < infos.size(); ++i) {
		const QString& name = infos.at(i);

		if (name.endsWith(QLatin1String(".exe"), Qt::CaseInsensitive)) 
			devConApp = QDir(driverDir).absoluteFilePath(name);
		else if (name.endsWith(QLatin1String(".inf"), Qt::CaseInsensitive))
			tapInf = name;
		else if (name.endsWith(QLatin1String(".sys"), Qt::CaseInsensitive))
			tapHwid = QFileInfo(name).baseName();

		if (!devConApp.isEmpty() && !tapHwid.isEmpty() && !tapInf.isEmpty())
			return true;
	}

	return false;
}

bool TapDriverManagerPrivate::isTapDriverInstalled()
{
	if (!probeTapDriverInf()) {
		qDebug() << "get tap driver information fail, " << driverDir;
		return false;
	}

	QStringList params;
	params << QLatin1String("hwids") << tapHwid;

	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardOutput()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardError()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	QEventLoop eventLoop;
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->drvProc, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(300000, &eventLoop, SLOT(quit()));

	this->drvProc.setWorkingDirectory(driverDir);

	qDebug() << devConApp << params.join(QLatin1Char(' '));
	this->drvProc.start(devConApp, params);
	if (this->drvProc.waitForStarted(30000)) {
		eventLoop.exec();
	} else {
		qDebug() << "TAP driver check process failed!";
	}

	if (this->drvProc.state() != QProcess::NotRunning) {
		qint64 pid = this->drvProc.processId();
		if (pid)
			ProcessUtil::killProcess(pid);
		else
			this->drvProc.kill();
	}

	this->readTapDriverData();	// QEventLoop退出, 可能在readyReadStandard...()被回调前
	QObject::disconnect(&this->drvProc, 0, 0, 0);
	return this->drvAvailable;
}

int TapDriverManagerPrivate::getTapDeviceCount()
{
	if (!probeTapDriverInf()) {
		qDebug() << "get tap driver information fail, " << driverDir;
		return false;
	}

	QStringList params;
	params << QLatin1String("hwids") << tapHwid;

	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardOutput()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardError()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	QEventLoop eventLoop;
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->drvProc, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(300000, &eventLoop, SLOT(quit()));

	this->drvProc.setWorkingDirectory(driverDir);

	qDebug() << devConApp << params.join(QLatin1Char(' '));
	this->drvProc.start(devConApp, params);
	if (this->drvProc.waitForStarted(30000)) {
		eventLoop.exec();
	} else {
		qDebug() << "TAP driver check process failed";
	}

	if (this->drvProc.state() != QProcess::NotRunning) {
		qint64 pid = this->drvProc.processId();
		if (pid)
			ProcessUtil::killProcess(pid);
		else
			this->drvProc.kill();
	}

	this->readTapDriverData();	// QEventLoop退出, 可能在readyReadStandard...()被回调前
	QObject::disconnect(&this->drvProc, 0, 0, 0);
	return this->drvCount;
}

bool TapDriverManagerPrivate::installTapDriver()
{
	if (!probeTapDriverInf()) {
		qDebug() << "get tap driver information fail, " << driverDir;
		return false;
	}

	QStringList params;
	params << QLatin1String("install") << tapInf << tapHwid;

	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardOutput()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardError()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	QEventLoop eventLoop;
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->drvProc, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(300000, &eventLoop, SLOT(quit()));

	this->drvProc.setWorkingDirectory(driverDir);

	qDebug() << devConApp << params.join(QLatin1Char(' '));
	this->drvProc.start(devConApp, params);
	if (this->drvProc.waitForStarted(30000)) {
		eventLoop.exec();
	} else {
		qDebug() << "TAP driver install process failed!";
	}

	if (this->drvProc.state() != QProcess::NotRunning) {
		qint64 pid = this->drvProc.processId();
		if (pid)
			ProcessUtil::killProcess(pid);
		else
			this->drvProc.kill();
	}

	this->readTapDriverData();	// QEventLoop退出, 可能在readyReadStandard...()被回调前
	QObject::disconnect(&this->drvProc, 0, 0, 0);
	return this->drvInstalledSuccess;
}

bool TapDriverManagerPrivate::removeTapDriver()
{
	if (!this->isTapDriverInstalled()) {
		qDebug() << "No tap devices available.";
		return true;
	}

	if (!probeTapDriverInf()) {
		qDebug() << "get tap driver information fail, " << driverDir;
		return false;
	}

	QStringList params;
	params << QLatin1String("remove") << tapHwid;

	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardOutput()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardError()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	QEventLoop eventLoop;
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->drvProc, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(300000, &eventLoop, SLOT(quit()));

	this->drvProc.setWorkingDirectory(driverDir);

	qDebug() << devConApp << params.join(QLatin1Char(' '));
	this->drvProc.start(devConApp, params);
	if (this->drvProc.waitForStarted(30000)) {
		eventLoop.exec();
	} else {
		qDebug() << "TAP driver remove process failed!";
	}

	if (this->drvProc.state() != QProcess::NotRunning) {
		qint64 pid = this->drvProc.processId();
		if (pid)
			ProcessUtil::killProcess(pid);
		else
			this->drvProc.kill();
	}

	QObject::disconnect(&this->drvProc, 0, 0, 0);
	return this->drvRemovedSuccess;
}

bool TapDriverManagerPrivate::enableTapDriver()
{
	if (!this->isTapDriverInstalled()) {
		qDebug() << "No tap devices available.";
		return false;
	}

	if (!probeTapDriverInf()) {
		qDebug() << "get tap driver information fail, " << driverDir;
		return false;
	}

	QStringList params;
	params << QLatin1String("enable") << tapHwid;

	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardOutput()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardError()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	QEventLoop eventLoop;
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->drvProc, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(300000, &eventLoop, SLOT(quit()));

	this->drvProc.setWorkingDirectory(driverDir);

	qDebug() << devConApp << params.join(QLatin1Char(' '));
	this->drvProc.start(devConApp, params);
	if (this->drvProc.waitForStarted(30000)) {
		eventLoop.exec();
	} else {
		qDebug() << "TAP driver enable process failed!";
	}

	if (this->drvProc.state() != QProcess::NotRunning) {
		qint64 pid = this->drvProc.processId();
		if (pid)
			ProcessUtil::killProcess(pid);
		else
			this->drvProc.kill();
	}

	QObject::disconnect(&this->drvProc, 0, 0, 0);
	return this->drvEnableSuccess;
}

bool TapDriverManagerPrivate::disableTapDriver()
{
	if (!this->isTapDriverInstalled()) {
		qDebug() << "No tap devices available.";
		return true;
	}

	if (!probeTapDriverInf()) {
		qDebug() << "get tap driver information fail, " << driverDir;
		return false;
	}

	QStringList params;
	params << QLatin1String("disable") << tapHwid;

	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardOutput()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(readyReadStandardError()), this, SLOT(readTapDriverData()));
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	QEventLoop eventLoop;
	QObject::connect(&this->drvProc, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->drvProc, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(300000, &eventLoop, SLOT(quit()));

	this->drvProc.setWorkingDirectory(driverDir);

	qDebug() << devConApp << params.join(QLatin1Char(' '));
	this->drvProc.start(devConApp, params);
	if (this->drvProc.waitForStarted(30000)) {
		eventLoop.exec();
	} else {
		qDebug() << "TAP driver disable process failed!";
	}

	if (this->drvProc.state() != QProcess::NotRunning) {
		qint64 pid = this->drvProc.processId();
		if (pid)
			ProcessUtil::killProcess(pid);
		else
			this->drvProc.kill();
	}

	QObject::disconnect(&this->drvProc, 0, 0, 0);
	return this->drvDisableSuccess;
}

void TapDriverManagerPrivate::readTapDriverData() {
	QByteArray output = drvProc.readAllStandardOutput();
	if (output.isEmpty())
		output = drvProc.readAllStandardError();
	if (output.isEmpty())
		return;

	const QString lineConvert = QString::fromUtf8(output);
	const QStringList lines = lineConvert.split(QLatin1Char('\n'), QString::SkipEmptyParts);

	qDebug() << "TapDriverManagerServantPrivate::readTapDriverData()";
	for (int i = 0; i < lines.size(); ++i)
		qDebug() << lines.at(i).trimmed();

	if (lineConvert.contains(QRegularExpression("Drivers[\\x20|\\t]+installed[\\x20|\\t]+successfully",
			QRegularExpression::CaseInsensitiveOption))) {
		this->drvInstalledSuccess = true;
		this->drvAvailable = true;
	}

	if (lineConvert.contains(QRegularExpression("device\\(s\\)[\\x20|\\t]+were[\\x20|\\t]+removed",
			QRegularExpression::CaseInsensitiveOption)))
		this->drvRemovedSuccess = true;

	if (lineConvert.contains(QRegularExpression("device\\(s\\)[\\x20|\\t]+are[\\x20|\\t]+enabled",
			QRegularExpression::CaseInsensitiveOption))) {
		this->drvEnableSuccess = true;
		this->drvAvailable = true;
	}

	if (lineConvert.contains(QRegularExpression("device\\(s\\)[\\x20|\\t]+disabled",
			QRegularExpression::CaseInsensitiveOption)))
		this->drvDisableSuccess = true;

	QRegularExpression regexp("([\\d]+)matching[\\x20|\\t]+device\\(s\\)[\\x20|\\t]+found",
		QRegularExpression::CaseInsensitiveOption);
	QRegularExpressionMatch match = regexp.match(lineConvert);
	if (match.hasMatch()) {
//		qDebug() << "group0:" << match.captured(0) << "group1:" << match.captured(1);
		bool success = false;
		int val = match.captured(1).trimmed().toInt(&success);
		if (success)
			this->drvCount = val;
		this->drvAvailable = true;
	}
}

void TapDriverManagerPrivate::onProcessError(QProcess::ProcessError processError)
{
	qDebug() << Translate::translateProcessError(processError);
}

bool TapDriverManager::initialize(const QString& driverDir)
{
	this->driverDir = QDir(driverDir).absolutePath();
	return true;
}

void TapDriverManager::clear()
{
	this->driverDir.clear();
}

bool TapDriverManager::isTapDriverInstalled()
{
	TapDriverManagerPrivate privateImpl(driverDir);
	return privateImpl.isTapDriverInstalled();
}

int TapDriverManager::getTapDeviceCount()
{
	TapDriverManagerPrivate privateImpl(driverDir);
	return privateImpl.getTapDeviceCount();
}

bool TapDriverManager::installTapDriver()
{
	TapDriverManagerPrivate privateImpl(driverDir);
	return privateImpl.installTapDriver();
}

bool TapDriverManager::removeTapDriver()
{
	TapDriverManagerPrivate privateImpl(driverDir);
	return privateImpl.removeTapDriver();
}

bool TapDriverManager::enableTapDriver()
{
	TapDriverManagerPrivate privateImpl(driverDir);
	return privateImpl.enableTapDriver();
}

bool TapDriverManager::disableTapDriver()
{
	TapDriverManagerPrivate privateImpl(driverDir);
	return privateImpl.disableTapDriver();
}

#endif
