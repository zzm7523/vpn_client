#ifndef __VPN_AGENT_SERVANT_H__
#define __VPN_AGENT_SERVANT_H__

#include "../config/config.h"

#include <QProcess>
#include <QTimer>
#include <QFile>
#include <QUrl>
#include <QString>
#include <QList>

#include "../common/vpn_i_proxy.h"
#include "../common/vpn_i_skeleton.h"
#include "../common/vpn_edge.h"
#include "../common/vpn_statistics.h"
#include "../common/accessible_resource.h"
#include "../policy/policy_engine_i_proxy.h"

class VPNLogParser;

class VPNAgentServant: public QObject, public VPNAgentSkeleton
{
	Q_OBJECT
public:
	explicit VPNAgentServant(const QString& uniqueIdentify);

	virtual bool initialize(const QString& configDirectory, const QString& workingDirectory, const Context& ctx);
	virtual void clear(const Context& ctx);

	virtual bool registerPolicyEngine(const QHostAddress& hostAddress, quint16 port, const QString& engineUniqueIdentify,
		const Context& ctx);
	virtual void unregisterPolicyEngine(const Context& ctx);

	virtual bool registerObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx);
	virtual void unregisterObserver(const QHostAddress& hostAddress, quint16 port, const QString& observerUniqueIdentify,
		const Context& ctx);

	virtual bool registerInputAgent(const QHostAddress& hostAddress, quint16 port, const QString& inputAgentUniqueIdentify,
		const Context& ctx);
	virtual void unregisterInputAgent(const Context& ctx);

	virtual void connect(const ServerEndpoint& remote, const QStringList& params, const Context& ctx);
	virtual void disconnect(const Context& ctx);

private slots:
	void onUpdateStatistics();
	void onProcessError(QProcess::ProcessError error);
	void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
	void onProcessOutput();
	void onPolicyEngineDisconnected();
	void onInputAgentDisconnected();
	void onObserverDisconnected();
	void terminateVPN(bool silent = true, int waitTimeout = 10000);

private:
	QStringList generateVPNArguments(const ServerEndpoint& remote, const QStringList& params);
	QFile* openLogFile(const QString& workDir, const QString& logFileName);
	void backupLogFile(const QString& backupDir, const QString& logFileName);
	void readVPNEdge(const QString& edgeFileName);
	void saveVPNEdge(const QString& edgeFileName);
	void writeToVPNProcess(const QString& description, const QString& input);
	bool applyPolicy(PolicyEngineI::ApplyPoint point);
	void handleOpenVPNProgress(VPNLogParser& parser);
	void handleOpenVPNError(VPNLogParser& parser);
	bool handleOpenVPNInput(VPNLogParser& parser);
	bool extractTunnelInfo(VPNLogParser& parser);
	void deleteARP();

	template <typename T>
	void notify_1(QArgument<T> t, const Context& ctx);
	
	template <typename T1, typename T2>
	void notify_2(QArgument<T1> t1, QArgument<T2> t2, const Context& ctx);

	VPNAgentI::State state;
	VPNAgentI::Error error;
	QString errorReason;
	Context connectCtx;
	bool requestCancel;
	bool initializationSequenceCompleted;

	QString configDirectory;
	QString workingDirectory;
	VPNEdge edge;	// 跨连接信息
	VPNTunnel tunnel;
	QList<AccessibleResource> accessibleResources;
	VPNStatistics baseStats;
	VPNStatistics currStats;

	QTimer statsTimer;
	QString exitEventName;
	QByteArray logBuffer;
	QFile *logFile;
	QProcess *vpnProcess;
	qint64 vpnProcessId;

	PolicyEngineProxy *frontEngineProxy;
	PolicyEngineI *backPolicyEngineI;

	VPNInputAgentProxy *inputAgentProxy;
	QList<VPNObserverProxy*> observerProxys;

	static quint32 nextExitEventId;

};

#endif

