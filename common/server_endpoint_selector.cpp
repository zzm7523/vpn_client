#include <QEventLoop>
#include <QProcess>
#include <QTimer>
#include <QTime>

#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <ipexport.h>
#include <IPHlpApi.h>
#include <IcmpAPI.h>
#endif

#include "server_endpoint_selector.h"

#ifdef _WIN32
#pragma warning(disable:4100)
#endif

void PingThread::run()
{
	int n_loop = 0, t_success = 0, n_consume_time = -1, t_consume_time = 0;
	bool result = false;
	const QByteArray host = this->remote.getHost().toLocal8Bit();
	const char *remote_addr = host.constData();

	do {	
		if (icmpPing(remote_addr, this->timeout, &n_consume_time)) {
			result = true;
			++t_success;
			t_consume_time += n_consume_time;
			emit progress(true, n_consume_time, this->remote);
		} else {
			emit progress(false, -1, this->remote);
		}

	} while (++n_loop < this->count);

	emit resultReady(result, t_success ? t_consume_time / t_success : 0xFFFF,
		((float) (this->count - t_success)) / this->count, this->remote);
}

bool PingThread::icmpPing(const char *address, int timeout, int *consume_time) 
{
#ifdef _WIN32
	struct addrinfo *res = NULL;
	struct sockaddr_in6 addr6_dest;
	struct sockaddr_in6 addr6_src;
	unsigned long addr4 = 0;

	HANDLE icmp_file;
	IP_OPTION_INFORMATION ip_info = { 255, 0, 0, 0, NULL };

	DWORD rz;
	int ai_family;
	char send_buf[64];
	char recv_buf[1024];

	if (getaddrinfo(address, NULL, NULL, &res) != 0)
		return FALSE;

	memset(&addr6_dest, 0x0, sizeof(struct sockaddr_in6));
	memset(&addr6_src, 0x0, sizeof(struct sockaddr_in6));

	ai_family = res->ai_family;

	if (ai_family == AF_INET6) {
		addr6_src.sin6_family = AF_INET6;
		addr6_src.sin6_flowinfo = 0;
		addr6_src.sin6_port = 0;
		addr6_src.sin6_scope_id = 0;      
		addr6_src.sin6_addr = in6addr_any;
		addr6_dest = *(sockaddr_in6*) (res->ai_addr);
		icmp_file = Icmp6CreateFile();
	} else {
		addr4 = ((sockaddr_in*) (res->ai_addr))->sin_addr.s_addr;
		icmp_file = IcmpCreateFile();
	}

	freeaddrinfo(res);

    if (icmp_file == INVALID_HANDLE_VALUE) {
		return FALSE;
    }    

	memset(send_buf, 'X', sizeof(send_buf));

	if (ai_family == AF_INET6)
		rz = Icmp6SendEcho2(icmp_file, NULL, NULL, NULL, &addr6_src, &addr6_dest, send_buf, sizeof(send_buf),
				&ip_info, recv_buf, sizeof(recv_buf), timeout);
	else
		rz = IcmpSendEcho(icmp_file, addr4, send_buf, sizeof(send_buf), NULL, recv_buf, sizeof(recv_buf), timeout);

	IcmpCloseHandle(icmp_file);

    if (rz == 0) {
		return FALSE;
	} else {
		if (ai_family == AF_INET6) {
			PICMPV6_ECHO_REPLY echo_reply = (PICMPV6_ECHO_REPLY) recv_buf;
			*consume_time = echo_reply->RoundTripTime;
			return echo_reply->Status == IP_SUCCESS ? TRUE : FALSE;
		} else {
	        PICMP_ECHO_REPLY echo_reply = (PICMP_ECHO_REPLY) recv_buf;
			*consume_time = echo_reply->RoundTripTime;
			return echo_reply->Status == IP_SUCCESS ? TRUE : FALSE;
		}
    }

#else
    Q_UNUSED(address)
    Q_UNUSED(timeout)

    QStringList params;
    params << this->remote.getHost( )<< "-c" << QString::number(1) << "-w" << QString::number(this->timeout / 1000);

    QTime start_time = QTime::currentTime();
    if (QProcess::execute("ping", params) == 0) {
        QTime end_time = QTime::currentTime();
        *consume_time = start_time.msecsTo(end_time);
		return true;
	} else {
		return false;
	}
#endif
}

ServerEndpoint BalanceSelectorPrivate::select(const QList<ServerEndpoint>& serverEndpoints)
{
	Q_ASSERT(serverEndpoints.size() > 0);

	QEventLoop eventLoop;
	PingThread *thread;

	QObject::connect(this, SIGNAL(resultReady()), &eventLoop, SLOT(quit()));
	QTimer::singleShot(5000, &eventLoop, SLOT(quit()));	// 5秒

	this->threadStartNum = serverEndpoints.size();
	this->threadStopNum = 0;
	this->firstSuccess = true;

	for (int i = 0; i < serverEndpoints.size(); ++i) {
		thread = new PingThread(serverEndpoints.at(i), MAX_PING_TIMEOUT, MAX_PING_COUNT);
		QObject::connect(thread, &PingThread::resultReady, this, &BalanceSelectorPrivate::handlePingResult);
		QObject::connect(thread, &PingThread::finished, thread, &QObject::deleteLater);
		thread->start();
	}

	eventLoop.exec();

	return selected;
}

void BalanceSelectorPrivate::handlePingResult(bool result, int average_time, float loss_rate, const ServerEndpoint& remote)
{
    Q_UNUSED(average_time)
    Q_UNUSED(loss_rate)

	++this->threadStopNum;

	if (result) {
		if (this->firstSuccess) {	// 保存第一个PING成功的服务端, 忽略其它
			this->firstSuccess = false;
			this->selected = remote;
		}
	}

	if (result || this->threadStartNum == this->threadStopNum) {
		emit resultReady();
	}
}

void ServerEndpointSelector::initialize(ServerEndpointSelector::Algorithm algorithm,
	const QList<ServerEndpoint>& staticEndpoints, const QList<ServerEndpoint>& dynamicEndpoints)
{
	this->algorithm = algorithm;
	this->selected.clear();
	this->serverEndpoints = staticEndpoints;
	for (int i = 0; i < dynamicEndpoints.size(); ++i) {
		ServerEndpoint endpoint = dynamicEndpoints.at(i);
		if (!this->serverEndpoints.contains(endpoint))
			this->serverEndpoints.append(endpoint);
	}
}

void ServerEndpointSelector::initialize(ServerEndpointSelector::Algorithm algorithm,
	const QList<ServerEndpoint>& staticEndpoints, const QList<ServerEndpoint>& dynamicEndpoints,
	const ServerEndpoint& optimized)
{
	this->algorithm = algorithm;
	// selected, optimized可能指向同一对象
//	this->selected.clear();
	this->serverEndpoints = staticEndpoints;
	QListIterator<ServerEndpoint> it(dynamicEndpoints);
	while (it.hasNext()) {
		ServerEndpoint endpoint = it.next();
		if (!this->serverEndpoints.contains(endpoint))
			this->serverEndpoints.append(endpoint);
	}

	if (!optimized.isEmpty() && this->serverEndpoints.contains(optimized)) {
		this->selected = optimized;
		this->serverEndpoints.removeOne(optimized);
	} else {
		this->selected.clear();
	}
}

void ServerEndpointSelector::clear()
{
	this->serverEndpoints.clear();
	this->selected.clear();
}

bool ServerEndpointSelector::select()
{
	this->selected.clear();	// 清理上一次选择

	if (this->serverEndpoints.size() > 1) {	
		if (ServerEndpointSelector::Balance == this->algorithm) {
			BalanceSelectorPrivate privateImpl;
			this->selected = privateImpl.select(this->serverEndpoints);
			if (!this->selected.isEmpty())
				this->serverEndpoints.removeOne(this->selected);

		} else if (ServerEndpointSelector::Sequence == this->algorithm) {
			this->selected = this->serverEndpoints.at(0);
			this->serverEndpoints.removeAt(0);
		}
	
		if (this->selected.isEmpty()) {	// 选择失败, 随机选择一个
			int x = rand() % this->serverEndpoints.size();
			this->selected = this->serverEndpoints.at(x);
			this->serverEndpoints.removeAt(x);
		}

	} else if (this->serverEndpoints.size() == 1) {
		this->selected = this->serverEndpoints.at(0);
		this->serverEndpoints.removeOne(this->selected);
	}

	return !this->selected.isEmpty();
}

const ServerEndpoint& ServerEndpointSelector::getServerEndpoint() const
{
	return this->selected;
}
