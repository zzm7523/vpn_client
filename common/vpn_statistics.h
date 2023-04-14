#ifndef __VPN_STATISTICS_H__
#define __VPN_STATISTICS_H__

#include "../config/config.h"

#include <QString>
#include <QDateTime>
#include <QDataStream>

class VPNStatistics
{
public:
	VPNStatistics();

#ifdef _WIN32
	void updateByteCount(unsigned long ifIndex, const QDateTime& updateTime,
		const VPNStatistics& baseStats = VPNStatistics());
#else
	void updateByteCount(const QString& ifName, const QDateTime& updateTime,
		const VPNStatistics& baseStats = VPNStatistics());
#endif
	// TODO 更新其它统计

	bool isEmpty() const;
	void clear();

	quint64 getUpdateTime() const;
	void setUpdateTime(quint64 updateTime);

	float getRecvSpeed() const;
	float getSentSpeed() const;

	quint64 getReadBytes() const;
	void setReadBytes(quint64 readBytes);

	quint64 getWriteBytes() const;
	void setWriteBytes(quint64 writeBytes);

private:
	friend QDataStream& operator<<(QDataStream& stream, const VPNStatistics& stats);
	friend QDataStream& operator>>(QDataStream& stream, VPNStatistics& stats);

	// millisecond
	quint64 updateTime;

	// 收发速度, 精度(kbps)
	float recvSpeed;
	float sentSpeed;

	// 流量数据, 精度(秒)
	quint64 readBytes;
	quint64 writeBytes;

	// 每个类的serial_uid都不同
	static const quint32 serial_uid;

};

#endif
