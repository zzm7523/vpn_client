#include <QCoreApplication>
#include <QDataStream>
#include <QByteArray>
#include <QBuffer>
#include <QEventLoop>
#include <QDebug>

#include "connection.h"
#include "locator.h"
#include "request_dispatcher.h"

#ifdef _WIN32
#pragma warning(disable:4189)
#endif

QQueue<Request*> TcpConnection::globalRequestQueue;			// 只有分发线程访问
QMap<quint32, Response*> TcpConnection::globalResponseMap;	// 只有分发线程访问

quint32 TcpConnection::globalNextRequestId = quint32(0);
QMutex TcpConnection::globalRefCountMutex;

const unsigned int Request::serial_uid  = 0x717171;
const unsigned int Response::serial_uid = 0x929292;

Invoke::Invoke(QObject *parent)
	: QObject(parent), requestId(quint32(0))
{
}

void Invoke::doRecvResponse(quint32 requestId)
{
	if (this->requestId == requestId)
		emit done();
}

Response* Invoke::invoke(Request *request, QEventLoop::ProcessEventsFlag flags)
{
	TcpConnection *connection = request->getConnection();
	Q_ASSERT (connection && connection->getRefCount() != 0);
	if (!connection || connection->state() != QAbstractSocket::ConnectedState) {
		throw SocketException(__FILE__, __LINE__, "Connection is disconnected");
	}

	Response *response = NULL;
	requestId = connection->sendRequest(request);
	if (!request->isOneway()) {
		QEventLoop eventLoop;
		QObject::connect(this, SIGNAL(done()), &eventLoop, SLOT(quit()));
		QObject::connect(connection, SIGNAL(recvResponse(quint32)), this, SLOT(doRecvResponse(quint32)));
		QObject::connect(connection, SIGNAL(error(QAbstractSocket::SocketError)), &eventLoop, SLOT(quit()));
		QObject::connect(connection, SIGNAL(disconnected()), &eventLoop, SLOT(quit()));

		eventLoop.exec(flags);
		response = TcpConnection::globalResponseMap.take(requestId);

		QObject::disconnect(this, 0, &eventLoop, 0);
		QObject::disconnect(connection, 0, &eventLoop, 0);
	}

	if (response && Response::SUCCESS != response->getStatusCode())
		qDebug() << "Invoke fail, " << request->getType() << "::" << request->getMethod() << response->getReasonPhrase() << "\n";
	return response;
}

TcpConnection::TcpConnection(QObject *parent)
	: QTcpSocket(parent), refCount(0), processingBlockSize(quint32(0))
{
#ifdef _DEBUG
	this->setReadBufferSize(1024);	// 调试用
#endif
	QObject::connect(this, SIGNAL(disconnected()), this, SLOT(doDisconnected()));
	QObject::connect(this, SIGNAL(readyRead()), this, SLOT(doReadMessage()));
}

TcpConnection::~TcpConnection() 
{
	QObject::disconnect(this, SIGNAL(disconnected()), this, 0);
}

int TcpConnection::getRefCount() const
{
	QMutexLocker locker(&globalRefCountMutex);
	int currRefCount = refCount;
	return currRefCount;
}

void TcpConnection::incRefCount()
{
	QMutexLocker locker(&globalRefCountMutex);
	++refCount;
}

void TcpConnection::decRefCount()
{
	QMutexLocker locker(&globalRefCountMutex);
	Q_ASSERT (refCount != 0);

	if (--refCount == 0) {
#ifndef _DEBUG
		this->deleteLater();
#endif
	}
}

bool TcpConnection::event(QEvent *e)
{
	if (e->type() == QEvent::Type(REQUEST_EVENT)) {
		RequestDispatcher::dispatch();
		e->accept();
		return true;
	} else if (e->type() == QEvent::Type(RESPONSE_EVENT)) {
		QMapIterator<quint32, Response*> i(globalResponseMap);
		while (i.hasNext()) {
			quint32 requestId = i.next().key();
			emit recvResponse(requestId);
		}
		e->accept();
		return true;
	} else {
		return QTcpSocket::event(e);
	}
}

quint32 TcpConnection::sendRequest(Request *request)
{
	Q_ASSERT(!request->getType().isEmpty() && !request->getObject().isEmpty() && !request->getMethod().isEmpty());

	QByteArray block;
	QDataStream out(&block, QIODevice::WriteOnly);
	out.setVersion(QDataStream::Qt_5_2);

	quint32 requestId = ++globalNextRequestId;
	request->setRequestId(requestId);
	out << quint32(0) << Request::serial_uid << requestId;
	out << request->getType() << request->getObject() << request->getMethod() << request->getParams() << request->isOneway();

	out.device()->seek(0);
	out << quint32(block.size() - sizeof(quint32));

	QMutexLocker locker(&this->socketMutex);

	qint64 len = this->write(block);
	if (len != block.size()) {
		throw SocketException(__FILE__, __LINE__, "write socket exception");
	}

	return requestId;
}

quint32 TcpConnection::sendResponse(Response *response)
{
	Q_ASSERT(response && response->getRequestId() != 0);

	QByteArray block;
	QDataStream out(&block, QIODevice::WriteOnly);
	out.setVersion(QDataStream::Qt_5_2);

	quint32 requestId = response->getRequestId();
	out << quint32(0) << Response::serial_uid << requestId;
	out << response->getStatusCode() << response->getReasonPhrase() << response->getResult();

	out.device()->seek(0);
	out << quint32(block.size() - sizeof(quint32));

	QMutexLocker locker(&this->socketMutex);

	qint64 len = this->write(block);
	if (len != block.size()) {
		throw SocketException(__FILE__, __LINE__, "write socket exception");
	}

	return requestId;
}

void TcpConnection::doDisconnected()
{
	Locator::unregisterConnection(this);

	QMutableListIterator<Request*> i(TcpConnection::globalRequestQueue);
	Request *request = NULL;

	// 失去连接时, 删除所有未处理的请求
	while (i.hasNext()) {
		request = i.next();
		if (request && request->getConnection() == this) {
			i.remove();
			delete request;
		}
	}
}

void TcpConnection::doReadMessage()
{
	do {		
		this->dataBuffer.append(this->readAll());	// 缓存所有读取数据

		if (this->processingBlockSize == 0) {	// 读取请求块的长度
			if (quint32(this->dataBuffer.size()) < sizeof(quint32))
				return;

			QDataStream headerIn(this->dataBuffer);
			headerIn.setVersion(QDataStream::Qt_5_2);

			headerIn >> this->processingBlockSize;
			Q_ASSERT(this->processingBlockSize > 0);
			this->dataBuffer.remove(0, sizeof(quint32));	
		}

		// 未接收到完整请求块 
		if (quint32(this->dataBuffer.size()) < this->processingBlockSize)
			return;

		// 接收到完整请求块
		QDataStream dataIn(this->dataBuffer);
		dataIn.setVersion(QDataStream::Qt_5_2);

		unsigned int local_serial_uid;
		quint32 requestId;

		dataIn >> local_serial_uid >> requestId;

		if (Request::serial_uid == local_serial_uid) {
			QString type, object, method;
			QStringList params;
			bool oneway;

			dataIn >> type >> object >> method >> params >> oneway;

			Request *request = new Request(type, object, method, params, oneway);
			request->setConnection(this);
			request->setRequestId(requestId);
			TcpConnection::globalRequestQueue.enqueue(request);
			QCoreApplication::postEvent(this, new QEvent(QEvent::Type(REQUEST_EVENT)));

		} else if (Response::serial_uid == local_serial_uid) {
			quint32 statusCode;
			QString reasonPhrase, result;

			dataIn >> statusCode >> reasonPhrase >> result;

			Response *response = new Response(requestId, statusCode, reasonPhrase, result);
			TcpConnection::globalResponseMap.insert(response->getRequestId(), response);
			QCoreApplication::postEvent(this, new QEvent(QEvent::Type(RESPONSE_EVENT)));

		} else
			Q_ASSERT(false);

		Q_ASSERT(this->processingBlockSize > 0);
		this->dataBuffer.remove(0, this->processingBlockSize);
		this->processingBlockSize = 0;

	} while (true);
}
