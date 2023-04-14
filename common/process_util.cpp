#include <QRegularExpression>
#include <QEventLoop>
#include <QTimer>
#include <QFile>
#include <QDebug>

#include "process_util.h"
#include "translate.h"

#include <stdlib.h>

#ifdef _WIN32
#pragma warning(disable:4100)

#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif
#include <Psapi.h>
#include <DbgHelp.h>
#endif

const unsigned int ExecuteResult::serial_uid = 0x532;

QDataStream& operator<<(QDataStream& stream, const ExecuteResult& result)
{
	stream << ExecuteResult::serial_uid << result.result << result.reason << result.exit << result.output;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, ExecuteResult& result)
{
	unsigned int local_serial_uid;

	stream >> local_serial_uid >> result.result >> result.reason >> result.exit >> result.output;

	Q_ASSERT(ExecuteResult::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}

bool ExecutorPrivate::execute(const int msecs, int *exitCode, QString& output)
{
	if (!QFile(program).exists()) {	// program不存在时, 不调用, 否则QT内存崩溃(? BUG)
		qDebug() << program << " don't exist";
		return false;
	}

	QObject::connect(&this->process, SIGNAL(readyReadStandardOutput()), this, SLOT(readOutput()));
	QObject::connect(&this->process, SIGNAL(readyReadStandardError()), this, SLOT(readOutput()));
	QObject::connect(&this->process, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
		SLOT(onProcessError(QProcess::ProcessError)));

	Q_ASSERT(msecs > 5000);	// 最小5秒

	QEventLoop eventLoop;
	QObject::connect(&this->process, SIGNAL(errorOccurred(QProcess::ProcessError)), &eventLoop, SLOT(quit()));
	QObject::connect(&this->process, SIGNAL(finished(int, QProcess::ExitStatus)), &eventLoop, SLOT(quit()));
	QTimer::singleShot(msecs < 5000 ? 5000 : msecs, &eventLoop, SLOT(quit()));

	bool result = true;
	qDebug() << program << arguments.join(QLatin1Char(' '));
	this->process.setWorkingDirectory(this->workDir);

	this->process.start(program, arguments);
	// Calling waitForStarted(...) from the main (GUI) thread might cause your user interface to freeze.
	if (/*this->process.waitForStarted(3000) &&*/ this->process.state() != QProcess::NotRunning) {
		eventLoop.exec();
	} else {
		result = false;
		qDebug() << "start " << program << " failed";
	}

	if (this->process.state() != QProcess::NotRunning) {
		// 优先选用ProcessUtil::killProcess(...)
#ifdef _WIN32
		qint64 pid = this->process.processId();
		if (pid)
			ProcessUtil::killProcess(pid);
		else
#endif
			this->process.kill();
	}

	this->readOutput();	// QEventLoop退出, 可能在readyReadStandard...()被回调前

	QObject::disconnect(&this->process, 0, 0, 0);
	*exitCode = this->process.exitCode();
	if (this->codec)
		output.append(this->codec->toUnicode(this->innerOutput));
	else
		output.append(QString::fromLocal8Bit(this->innerOutput));

	return result;
}

void ExecutorPrivate::readOutput()
{
	this->innerOutput.append(process.readAllStandardOutput());
	this->innerOutput.append(process.readAllStandardError());

	QString text;
	if (this->codec)
		text.append(this->codec->toUnicode(this->innerOutput));
	else
		text.append(QString::fromLocal8Bit(this->innerOutput));

	QStringList lines = text.split(QLatin1Char('\n'), QString::SkipEmptyParts);
	for (int i = 0; i < lines.size(); ++i)
		qDebug() << lines.at(i).trimmed();
}

void ExecutorPrivate::onProcessError(QProcess::ProcessError processError)
{
	this->reason = Translate::translateProcessError(processError);
	qDebug() << this->reason;
}

#ifdef _WIN32

// Iterate the top-level windows
class WindowIterator
{
public:
	WindowIterator(DWORD nAlloc = 1024) : m_current(0), m_count(0) {
		m_hwnds = new HWND[nAlloc];
		m_nAlloc = nAlloc;
	}

	~WindowIterator() {
		delete [] m_hwnds;
	}

	HWND next() {
		return m_hwnds && m_current < m_count ? m_hwnds[m_current++] : NULL;
	}

	HWND first() {
		::EnumWindows(enumProc, (LPARAM) this);
		m_current = 0;
		return next();
	}

	DWORD getCount() const {
		return m_count;
	}

protected:
	static BOOL CALLBACK enumProc(HWND hwnd, LPARAM lp) {
		return ((WindowIterator*) lp)->onEnumProc(hwnd);
	}

	// virtual enumerator
	virtual BOOL onEnumProc(HWND hwnd) {
		if (onWindow(hwnd)) {
			if (m_count < m_nAlloc)
				m_hwnds[m_count++] = hwnd;
		}
		return TRUE; // keep looking
	}

	// override to filter different kinds of windows
	virtual BOOL onWindow(HWND hwnd) {
		return TRUE;
	}

	HWND* m_hwnds;		// array of hwnds for this PID
	DWORD m_nAlloc;		// size of array
	DWORD m_count;		// number of HWNDs found
	DWORD m_current;	// current HWND

};

// Iterate the top-level windows in a process
class MainWindowIterator : public WindowIterator
{
public:
	MainWindowIterator(DWORD pid, BOOL bVis = TRUE, DWORD nAlloc = 1024)
		: WindowIterator(nAlloc), m_pid(pid), m_bVisible(bVis) {
	}

	~MainWindowIterator() {
	}

protected:
	// OnWindow:: Is window's process ID the one i'm looking for?
	// Set m_bVisible=FALSE to find invisible windows too.
	virtual BOOL onWindow(HWND hwnd) {
		if (!m_bVisible || (GetWindowLong(hwnd,GWL_STYLE) & WS_VISIBLE)) {
			DWORD pidwin;
			GetWindowThreadProcessId(hwnd, &pidwin);
			if (pidwin == m_pid)
				return TRUE;
		}
		return FALSE;
	}

	DWORD m_pid;				// process id
	DWORD m_bVisible;			// show only visible windows

};

// Process iterator -- iterator over all system processes
// Always skips the first (IDLE) process with PID=0.
class ProcessIterator
{
public:
	ProcessIterator()
		: m_pids(NULL), m_count(0), m_current(0) {
	}

	~ProcessIterator() {
		delete [] m_pids;
	}

	DWORD first() {
		DWORD nalloc = 1024;
		m_current = (DWORD) -1;
		m_count = 0;

		do {
			delete [] m_pids;
			m_pids = new DWORD [nalloc];
			if (EnumProcesses(m_pids, nalloc * sizeof(DWORD), &m_count)) {
				m_count /= sizeof(DWORD);
				m_current = 1;						 // skip IDLE process
			}
		} while (nalloc <= m_count);

		return next();
	}

	DWORD next() {
		return m_pids && m_current < m_count ? m_pids[m_current++] : 0;
	}

	DWORD getCount() const {
		return m_count;
	}

protected:
	DWORD*	m_pids;			// array of procssor IDs
	DWORD	m_count;		// size of array
	DWORD	m_current;		// next array item
	
};

// Iterate the modules in a process. Note that the first module is the main EXE
// that started the process.
class ProcessModuleIterator
{
public:
	ProcessModuleIterator(DWORD pid)
			: m_hModules(NULL), m_count(0), m_current(0) {
		m_hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	}

	~ProcessModuleIterator() {
		CloseHandle(m_hProcess);
		delete [] m_hModules;
	}

	HMODULE first() {
		m_count = 0, m_current = (DWORD) -1; 
		m_hModules = NULL;

		if (m_hProcess) {
			DWORD nalloc = 1024;

			do {
				delete [] m_hModules;
				m_hModules = new HMODULE[nalloc];
				if (EnumProcessModules(m_hProcess, m_hModules, nalloc * sizeof(DWORD), &m_count)) {
					m_count /= sizeof(HMODULE);
					m_current = 0;
				}
			} while (nalloc <= m_count);
		}

		return next();
	}

	HMODULE next() {
		return m_hProcess && m_current < m_count ? m_hModules[m_current++] : 0;
	}

	DWORD getCount() const {
		return m_count;
	}

	HANDLE getProcessHandle() const {
		return m_hProcess;
	}

protected:
	HANDLE m_hProcess;		// process handle
	HMODULE *m_hModules;	// array of module handles
	DWORD m_count;			// size of array
	DWORD m_current;		// next module handle

};

ProcessInfo::ProcessInfo(DWORD _pid)
	: pid(_pid)
{
}

ProcessInfo::ProcessInfo()
	: pid(GetCurrentProcessId())
{
}

HMODULE ProcessInfo::getModuleHandle(const QStringList& funcNames, const QString& moduleName) const
{
#define MAX_FUNC_NAME	1024
	ProcessModuleIterator it(pid);
	HMODULE moduleHandle = it.first();
	QString moduleFullName;

	while (moduleHandle) {
		moduleFullName = getModuleFullName(moduleHandle);
		if (moduleName.isEmpty() || moduleFullName.endsWith(moduleName, Qt::CaseInsensitive)) {
			bool success = true;
			for (int i = 0; i < funcNames.size(); ++i) {
				if (!GetProcAddress(moduleHandle, funcNames.at(i).toUtf8().data())) {
					success = false;
					break;
				}
			}
			if (success)
				return moduleHandle;
		}
		moduleHandle = it.next();
	}

	return 0;
}

QString ProcessInfo::getModuleFullName(HMODULE moduleHandle) const
{
#define MAX_FILE_NAME	4096
	wchar_t fileName[MAX_FILE_NAME];
	int fileNameSize = 0;

	if ((fileNameSize = GetModuleFileName(moduleHandle, fileName, MAX_FILE_NAME)))
		return QString::fromWCharArray(fileName, fileNameSize);

	return QString();
}

QString ProcessInfo::getModuleFullName(const QStringList& funcNames, const QString& moduleName) const
{
	HMODULE moduleHandle = getModuleHandle(funcNames, moduleName);
	return moduleHandle ? getModuleFullName(moduleHandle) : QString();
}

QString ProcessInfo::getModuleFullPath(const QStringList& funcNames, const QString& moduleName) const
{
	QString moduleFullPath;

	HMODULE moduleHandle = getModuleHandle(funcNames, moduleName);
	if (moduleHandle) {
		moduleFullPath = getModuleFullName(moduleHandle);
		int idx = moduleFullPath.lastIndexOf(QLatin1String("\\"));
		if (idx != -1)
			moduleFullPath = moduleFullPath.left(idx);
	}

	return moduleFullPath;
}

#endif

ProcessUtil::ProcessUtil() {
}

long ProcessUtil::findProcess(const QString& program)
{
#ifdef _WIN32
	ProcessIterator itp;

	for (DWORD pid = itp.first(); pid; pid = itp.next()) {
		const QString sModName = program;
		char name[_MAX_PATH];
		ProcessModuleIterator itm(pid);
		HMODULE hModule = itm.first(); // .EXE
	
		if (hModule) {
			GetModuleBaseNameA(itm.getProcessHandle(), hModule, name, _MAX_PATH);
			qDebug() << "ProcessUtil::findProcess(...)\t" << name;

			if (sModName.compare(QLatin1String(name), Qt::CaseInsensitive) == 0)
				return static_cast<long>(pid);
		}
	}
#else
	QString pattern = QLatin1String("^") + program + QLatin1String("$");
	ExecuteResult result = ProcessUtil::execute(QLatin1String("pgrep"), QStringList() << pattern);
	if (result.getExit() == 0) {
		bool ok = false;
		long pid = result.getOutput().toLong(&ok);
		if (ok)
			return pid;
	}
#endif

	return -1;
}

bool ProcessUtil::killProcess(quint64 pid)
{
	bool bKilled = true;

#ifdef _WIN32
	MainWindowIterator itw(pid);

	for (HWND hwnd = itw.first(); hwnd; hwnd = itw.next()) {
		DWORD_PTR bOKToKill = FALSE;
		
		SendMessageTimeout(hwnd, 15, 0, 0, SMTO_ABORTIFHUNG|SMTO_NOTIMEOUTIFNOTHUNG, 100, &bOKToKill);
		SendMessageTimeout(hwnd, WM_QUERYENDSESSION, 0, 0, SMTO_ABORTIFHUNG|SMTO_NOTIMEOUTIFNOTHUNG, 100, &bOKToKill);
		if (!bOKToKill)
			return false;  // window doesn't want to die: abort
		PostMessage(hwnd, WM_CLOSE, 0, 0);
	}
	
	// I've closed the main windows; now wait for process to die. 
	HANDLE hp = OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE, FALSE, (DWORD) pid);

	if (hp) {
		bKilled = TerminateProcess(hp, 1);
		CloseHandle(hp);
	}
#else
	if (0 == QProcess::execute(QLatin1String("kill"), QStringList() << QLatin1String("-9") << QString::number(pid)))
		bKilled = true;
#endif

	return bKilled;
}

#ifdef _WIN32
void ProcessUtil::start(const QString& program, const QStringList& arguments, const QString& workDir)
{
	Q_UNUSED(workDir);

	STARTUPINFOA start_info;
	PROCESS_INFORMATION proc_info;
	QString cmdLine;

	if (program.contains(QRegularExpression("\\x20|\\t")))
		cmdLine.append("\"").append(program).append("\"");
	else
		cmdLine.append(program);

	for (int i = 0; i < arguments.size(); ++i) {
		if (arguments.at(i).contains(QRegularExpression("\\x20|\\t")))
			cmdLine.append(" ").append("\"").append(arguments.at(i)).append("\"");
		else
			cmdLine.append(" ").append(arguments.at(i));
	}

	char *cl = (char *) malloc((size_t) cmdLine.size() + 1);
	strcpy(cl, qPrintable(cmdLine));

	memset(&start_info, 0x0, sizeof(STARTUPINFOA));
	memset(&proc_info, 0x0, sizeof(PROCESS_INFORMATION));

	/* fill in STARTUPINFO struct */
	GetStartupInfoA (&start_info);
	start_info.cb = sizeof(start_info);
	start_info.dwFlags = STARTF_USESHOWWINDOW;
	start_info.wShowWindow = SW_HIDE;

	if (CreateProcessA(NULL, cl, NULL, NULL, FALSE, 0, NULL, NULL, &start_info, &proc_info)) {
		CloseHandle(proc_info.hThread);
		CloseHandle(proc_info.hProcess);
	} else {
		qDebug() << "ProcessUtil::start(...) fail!, " << cmdLine;
	}
}
#endif

ExecuteResult ProcessUtil::execute(const QString& program, const QStringList& arguments)
{
	return ProcessUtil::execute(program, arguments, QLatin1String("."), NULL);
}

ExecuteResult ProcessUtil::execute(const QString& program, const QStringList& arguments, const QString& workDir,
	QTextCodec *codec)
{
#define MAX_PROCESS_TIMEOUT	300000	// 300秒

	int exit = 0;
	QString output;
	ExecutorPrivate executor(program, arguments, workDir, codec);
	bool result = executor.execute(MAX_PROCESS_TIMEOUT, &exit, output);
	return ExecuteResult(result, executor.getReason(), exit, output);
}

void ProcessUtil::crash()
{
	char *null = NULL;
	*null = 0;
}

#ifdef _WIN32

/*
#ifndef _M_IX86
#error "The following code only works for x86!"
#endif
*/

static inline HMODULE loadSystemDll(const char *pszName)
{
	char   szPath[MAX_PATH];
	UINT   cchPath = GetSystemDirectoryA(szPath, sizeof(szPath));
	size_t cbName  = strlen(pszName) + 1;

	if (cchPath + 1 + cbName > MAX_PATH)
		return NULL;

	szPath[cchPath] = '\\';
	memcpy(&szPath[cchPath + 1], pszName, cbName);
	return LoadLibraryA(szPath);
}

static inline BOOL IsDataSectionNeeded(const WCHAR *pModuleName)
{  
	if (pModuleName == 0) {  
		return FALSE;
	}

	WCHAR szFileName[_MAX_FNAME] = L"";
	_wsplitpath(pModuleName, NULL, NULL, szFileName, NULL);

	if (wcsicmp(szFileName, L"ntdll") == 0)
		return TRUE;  

	return FALSE;  
}  

static inline BOOL CALLBACK MiniDumpCallback(PVOID pParam, const PMINIDUMP_CALLBACK_INPUT pInput,
		PMINIDUMP_CALLBACK_OUTPUT pOutput)  
{  
	if (pInput == 0 || pOutput == 0)
		return FALSE;

	switch (pInput->CallbackType) {
	case ModuleCallback:
		if (pOutput->ModuleWriteFlags & ModuleWriteDataSeg) {
			if (!IsDataSectionNeeded(pInput->Module.FullPath))
				pOutput->ModuleWriteFlags &= (~ModuleWriteDataSeg);
		}
	case IncludeModuleCallback:
	case IncludeThreadCallback:
	case ThreadCallback:
	case ThreadExCallback:
		return TRUE;
	default:
		;
	}

	return FALSE;
}

static inline void CreateMiniDump(PEXCEPTION_POINTERS pep, LPCTSTR strFileName)
{  
	typedef BOOL  (WINAPI* lpMiniDumpWriteDump)(
		HANDLE hProcess,
		DWORD ProcessId,
		HANDLE hFile,
		MINIDUMP_TYPE DumpType,
		PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
		PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		PMINIDUMP_CALLBACK_INFORMATION CallbackParam
	);

	lpMiniDumpWriteDump MiniDumpWriteDump;

	HINSTANCE hDbgHelp = loadSystemDll("dbghelp.dll");
	if (hDbgHelp == NULL)
		return;

    MiniDumpWriteDump = (lpMiniDumpWriteDump) GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
	if (MiniDumpWriteDump == NULL)
		return;

	HANDLE hFile = CreateFile(strFileName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE)) {
		MINIDUMP_EXCEPTION_INFORMATION mdei;
		mdei.ThreadId           = GetCurrentThreadId();
		mdei.ExceptionPointers  = pep;
		mdei.ClientPointers     = FALSE;

		MINIDUMP_CALLBACK_INFORMATION mci;
		mci.CallbackRoutine     = (MINIDUMP_CALLBACK_ROUTINE) MiniDumpCallback;
		mci.CallbackParam       = 0;

		MiniDumpWriteDump(::GetCurrentProcess(), ::GetCurrentProcessId(), hFile, MiniDumpNormal,
				(pep != 0) ? &mdei : 0, NULL, &mci);

		CloseHandle(hFile);
	}
}

static LPCTSTR globalDumpFileName = NULL;

static LONG __stdcall MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
	if (globalDumpFileName && lstrlen(globalDumpFileName) > 0)
		CreateMiniDump(pExceptionInfo, globalDumpFileName);

	return EXCEPTION_EXECUTE_HANDLER;
}  

void ProcessUtil::enableMiniDump(const QString& dumpFileName)
{
	if (!dumpFileName.isEmpty()) {
		wchar_t *dumpFileName__ = NULL;

		globalDumpFileName = dumpFileName__ = new wchar_t[dumpFileName.size() * 4 + 2];
		memset(dumpFileName__, 0x0, dumpFileName.size() * 4 + 2);
		dumpFileName.toWCharArray(dumpFileName__);
	}

	// 注册异常处理函数
	// 经测试 VS2010 SP1 x86, VS2019 16.8.2 x64, 可以生成minidump文件
	SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
}

#endif
