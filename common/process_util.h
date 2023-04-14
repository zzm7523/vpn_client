#ifndef __PROCESS_UTIL_H__
#define __PROCESS_UTIL_H__

#include "../config/config.h"

#include <QProcess>
#include <QDataStream>
#include <QTextCodec>
#include <QString>
#include <QStringList>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

class ExecuteResult
{
public:
	ExecuteResult(bool _result, const QString& _reason, int _exit, const QString& _output)
		: result(_result), reason(_reason), exit(_exit), output(_output) {
	}

	ExecuteResult()
		: result(false), exit(-1) {
	}

	bool getResult() const {
		return result;
	}

	void setResult(bool result) {
		this->result = result;
	}

	const QString& getReason() const {
		return reason;
	}

	void setReason(const QString& reason) {
		this->reason = reason;
	}

	int getExit() const {
		return exit;
	}

	void setExit(int exit) {
		this->exit = exit;
	}

	const QString& getOutput() const {
		return output;
	}

	void setOutput(const QString& output) {
		this->output = output;
	}

private:
	friend QDataStream& operator<<(QDataStream& stream, const ExecuteResult& result);
	friend QDataStream& operator>>(QDataStream& stream, ExecuteResult& result);

	bool result;
	QString reason;

	int exit;
	QString output;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};

class ExecutorPrivate : public QObject
{
	Q_OBJECT
public:
	ExecutorPrivate(const QString& _program, const QStringList& _arguments, const QString& _workDir,
			QTextCodec *_codec) 
		: program(_program), arguments(_arguments), workDir(_workDir), codec(_codec) {
	}

	bool execute(int msecs, int *exitCode, QString& output);

	const QString& getReason() const {
		return reason;
	}

private slots:
	void readOutput();
	void onProcessError(QProcess::ProcessError processError);

private:
	QString program;
	QStringList arguments;
	QString workDir;
	QString reason;
	QByteArray innerOutput;
	QTextCodec *codec;
	QProcess process;

};

#ifdef _WIN32
class ProcessInfo
{
public:
	explicit ProcessInfo(DWORD pid);
	ProcessInfo();

	HMODULE getModuleHandle(const QStringList& funcNames, const QString& moduleName = QString()) const;
	QString getModuleFullName(HMODULE moduleHandle) const;
	QString getModuleFullName(const QStringList& funcNames, const QString& moduleName = QString()) const;
	QString getModuleFullPath(const QStringList& funcNames, const QString& moduleName = QString()) const;

private:
	DWORD pid;

};
#endif

class ProcessUtil
{
public:
#ifdef _WIN32
	static void enableMiniDump(const QString& dumpFileName = QString("core.dmp"));
	static void start(const QString& program, const QStringList& arguments, const QString& workDir);
#endif

	static long findProcess(const QString& program);
	static bool killProcess(quint64 pid);

	static void crash();

	static ExecuteResult execute(const QString& program, const QStringList& arguments);
	static ExecuteResult execute(const QString& program, const QStringList& arguments, const QString& workDir,
		QTextCodec *codec = NULL);

private:
	ProcessUtil();

};

#endif
