#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include "../config/config.h"

#include <QString>
#include <QDataStream>
#include <QEvent>
#include <QEventLoop>
#include <QMap>
#include <QQueue>
#include <QMutex>
#include <QTcpSocket>
#include <QHostAddress>

#define REQUEST_EVENT	quint16(QEvent::User) + 103
#define RESPONSE_EVENT	quint16(QEvent::User) + 201

class SocketException;
class TcpConnection;

class Request
{
public:
	/* !! 方法调用谨慎使用oneway请求, 不好同步 !! */
	Request()
		: requestId(0), oneway(false), connection(NULL) {
	}

	explicit Request(QDataStream &in)
		: requestId(0), oneway(false), connection(NULL) {
		in >> requestId >> type >> object >> method >> params >> oneway;
	}

	Request(const QString& _type, const QString& _object, const QString& _method, const QStringList& _params, bool _oneway) 
		: requestId(0), type(_type), object(_object), method(_method), params(_params), oneway(_oneway), connection(NULL) {
	}

	TcpConnection* getConnection() const {
		return connection;
	}

	void setConnection(TcpConnection* connection) {
		this->connection = connection;
	}

	quint32 getRequestId() const {
		return requestId;
	}

	void setRequestId(quint32 requestId) {
		this->requestId = requestId;
	}

	const QString& getType() const {
		return type;
	}

	void setType(const QString& type) {
		this->type = type;
	}

	const QString& getObject() const {
		return object;
	}

	void setObject(const QString& object) {
		this->object = object;
	}

	const QString& getMethod() const {
		return method;
	}

	void setMethod(const QString& method) {
		this->method = method;
	}

	const QStringList& getParams() const {
		return params;
	}

	void setParams(const QStringList& params) {
		this->params = params;
	}

	bool isOneway() const {
		return oneway;
	}

	void setOneway(bool oneway) {
		/* !! 方法调用谨慎使用oneway请求, 不好同步 !! */
		this->oneway = oneway;
	}

private:
	friend class TcpConnection;

	quint32 requestId;
	QString type;
	QString object;
	QString method;
	QStringList params;
	bool oneway;

	TcpConnection *connection;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};

class Response
{
public:
	enum StatusCode
	{
		SUCCESS	= 0,
		LOCATE_SERVANT_FAIL,
		LOCATE_METHOD_FAIL
	};

	Response() 
		: requestId(0), statusCode(SUCCESS), reasonPhrase(QString()), result(QString()) {
	}

	explicit Response(QDataStream &in) {
		in >> requestId >> statusCode >> reasonPhrase >> result;
	}

	Response(quint32 _requestId, bool _statusCode, const QString& _reasonPhrase = QString(), 
		const QString& _result = QString())
		: requestId(_requestId), statusCode(_statusCode), reasonPhrase(_reasonPhrase), result(_result) {
	}

	quint32 getRequestId() const {
		return requestId;
	}

	void setRequestId(quint32 requestId) {
		this->requestId = requestId;
	}

	quint32 getStatusCode() const {
		return statusCode;
	}

	void setStatusCode(quint32 statusCode) {
		this->statusCode = statusCode;
	}

	const QString& getReasonPhrase() const {
		return reasonPhrase;
	}

	void setReasonPhrase(const QString& reasonPhrase) {
		this->reasonPhrase = reasonPhrase;
	}

	const QString& getResult() const {
		return result;
	}

	void setResult(const QString& result) {
		this->result = result;
	}

private:
	friend class TcpConnection;

	quint32 requestId;
	quint32 statusCode;
	QString reasonPhrase;
	QString result;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};

class Invoke : public QObject
{
	Q_OBJECT
public:
	Invoke(QObject *parent = NULL);

	Response* invoke(Request *request, QEventLoop::ProcessEventsFlag flags = QEventLoop::AllEvents);

signals:
	void done();

private slots:
	void doRecvResponse(quint32 requestId);

private:
	quint32 requestId;

};

class SocketException
{
public:
	SocketException(const QString& _source, int _line, const QString& _message)
		: source(_source), line(_line), message(_message) {
	}
	const QString& getSource() const {
		return source;
	}
	int getLine() const {
		return line;
	}
	const QString& getMessage() const {
		return message;
	}

private:
	QString source;
	int line;
	QString message;

};

class TcpConnection : public QTcpSocket
{
	Q_OBJECT
public:
	// 只有主线程访问(事件分发线程访问, 不需要锁)
	static QQueue<Request*> globalRequestQueue;
	static QMap<quint32, Response*> globalResponseMap;

public:
	TcpConnection(QObject *parent = NULL);
	~TcpConnection();

	int getRefCount() const;
	void incRefCount();
	void decRefCount();

	virtual bool event(QEvent *e);

	quint32 sendRequest(Request *request);
	quint32 sendResponse(Response *response);

signals:
	void recvRequest(quint32 requestId);
	void recvResponse(quint32 requestId);

private slots:
	void doReadMessage();
	void doDisconnected();

private:
	static QMutex globalRefCountMutex;
	static quint32 globalNextRequestId;

	QMutex socketMutex;
	int refCount;

	quint32 processingBlockSize;
	QByteArray dataBuffer;

};

#endif
