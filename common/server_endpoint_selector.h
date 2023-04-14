#ifndef __SERVER_ENDPOINT_SELECTOR_H__
#define __SERVER_ENDPOINT_SELECTOR_H__

#include "../config/config.h"

#include <QList>
#include <QThread>

#include "server_endpoint.h"

// 微秒, 必须是1000的倍数; 因为linux平台ping命令行程序以秒为单位设置超时值
#define MAX_PING_TIMEOUT	1000
#define MAX_PING_COUNT		5

class PingThread : public QThread
{
	Q_OBJECT
public:
	PingThread(const ServerEndpoint& _remote, int _timeout, int _count)
		: remote(_remote), timeout(_timeout), count(_count) {
	}

	void run();

signals:
	void progress(bool result, int time, const ServerEndpoint& remote);
	void resultReady(bool result, int average_time, float loss_rate, const ServerEndpoint& remote);

private:
	bool icmpPing(const char *address, int timeout, int *consume_time);

	ServerEndpoint remote;
	int timeout;
	int count;

};

class BalanceSelectorPrivate : public QObject
{
	Q_OBJECT
public:
	BalanceSelectorPrivate()
		: QObject(), threadStartNum(0), threadStopNum(0), firstSuccess(false) {
	}

	ServerEndpoint select(const QList<ServerEndpoint>& serverEndpoints);

signals:
	void resultReady();

private slots:
	void handlePingResult(bool result, int average_time, float loss_rate, const ServerEndpoint& remote);

private:
	int threadStartNum;
	int threadStopNum;
	bool firstSuccess;
	ServerEndpoint selected;

};

class ServerEndpointSelector
{
public:
	enum Algorithm
	{
		Random = 0,
		Sequence,
		Balance
	};

	void initialize(ServerEndpointSelector::Algorithm algorithm, const QList<ServerEndpoint>& staticEndpoints,
		const QList<ServerEndpoint>& dynamicEndpoints);
	void initialize(ServerEndpointSelector::Algorithm algorithm, const QList<ServerEndpoint>& staticEndpoints,
		const QList<ServerEndpoint>& dynamicEndpoints, const ServerEndpoint& optimized);

	void clear();

	// 选择服务端点
	bool select();

	// 获取上一次选择的结果
	const ServerEndpoint& getServerEndpoint() const;

private:
	ServerEndpointSelector::Algorithm algorithm;
	ServerEndpoint selected;
	QList<ServerEndpoint> serverEndpoints;

};

#endif
