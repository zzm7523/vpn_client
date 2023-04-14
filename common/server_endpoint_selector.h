#ifndef __SERVER_ENDPOINT_SELECTOR_H__
#define __SERVER_ENDPOINT_SELECTOR_H__

#include "../config/config.h"

#include <QList>
#include <QThread>

#include "server_endpoint.h"

// ΢��, ������1000�ı���; ��Ϊlinuxƽ̨ping�����г�������Ϊ��λ���ó�ʱֵ
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

	// ѡ�����˵�
	bool select();

	// ��ȡ��һ��ѡ��Ľ��
	const ServerEndpoint& getServerEndpoint() const;

private:
	ServerEndpointSelector::Algorithm algorithm;
	ServerEndpoint selected;
	QList<ServerEndpoint> serverEndpoints;

};

#endif
