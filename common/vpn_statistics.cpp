#include <QDebug>

#include <stdint.h>
#include <inttypes.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#include <Iphlpapi.h>
#endif

#include "common.h"
#include "vpn_statistics.h"

const unsigned int VPNStatistics::serial_uid = 0x231;

#ifdef _WIN32
typedef NETIO_STATUS(NETIOAPI_API_ *pGetIfEntry2_t)(PMIB_IF_ROW2 Row);
static pGetIfEntry2_t pGetIfEntry2 = NULL;
static bool check_done = false;
#else
typedef struct {
	uint64_t ibytes;
	uint64_t ipackets;
	uint64_t ierr;
	uint64_t idrop;
	uint64_t obytes;
	uint64_t opackets;
	uint64_t oerr;
	uint64_t odrop;
	uint64_t colls;
} net_stat_t;

#define MAX_STRING_LEN 1024

static int get_net_stat(const char *if_name, net_stat_t *result)
{
	int	ret = 0;
	char line[MAX_STRING_LEN], name[MAX_STRING_LEN], *p = NULL;
	FILE *file;

	if (NULL == if_name || '\0' == *if_name) {
		qDebug() << "Network interface name cannot be empty.";
		return 0;
	}

	if (NULL == (file = fopen("/proc/net/dev", "r"))) {
		qDebug() << "Cannot open /proc/net/dev";
		return 0;
	}

	while (NULL != fgets(line, sizeof(line), file)) {
		if (NULL == (p = strstr(line, ":")))
			continue;

		*p = '\t';

		if (10 == sscanf(line, "%s\t%" PRIu64 "\t%" PRIu64 "\t%"
				PRIu64 "\t%" PRIu64 "\t%*s\t%*s\t%*s\t%*s\t%"
				PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%"
				PRIu64 "\t%*s\t%" PRIu64 "\t%*s\t%*s\n",
				name,
				&result->ibytes,	/* bytes */
				&result->ipackets,	/* packets */
				&result->ierr,		/* errs */
				&result->idrop,		/* drop */
				&result->obytes,	/* bytes */
				&result->opackets,	/* packets */
				&result->oerr,		/* errs */
				&result->odrop,		/* drop */
				&result->colls)) 	/* icolls */
		{
			if (0 == strcmp(name, if_name)) {
				ret = 1;
				break;
			}
		}
	}

	fclose(file);

	if (!ret) {
		qDebug() << "Cannot find information for this network interface in /proc/net/dev.";
		return 0;
	}

	return 1;
}
#endif

VPNStatistics::VPNStatistics()
	: updateTime(0), recvSpeed(0.0f), sentSpeed(0.0f), readBytes(0), writeBytes(0)
{
#ifdef _WIN32
	if (!check_done) {
		HMODULE	module;
		if ((module = GetModuleHandle(L"iphlpapi.dll"))) {
			if (!(pGetIfEntry2 = (pGetIfEntry2_t) GetProcAddress(module, "GetIfEntry2"))) {
				qDebug() << "GetProcAddress failed with error: " << GetLastError();
			}
		} else {
			qDebug() << "GetModuleHandle failed with error: " << GetLastError();
		}
		check_done = true;
	}
#endif
}

#ifdef _WIN32
void VPNStatistics::updateByteCount(unsigned long ifIndex, const QDateTime& updateTime,
		const VPNStatistics& baseStats)
{
	quint64 x_updateTime = updateTime.toMSecsSinceEpoch();
	quint64 time_interval = x_updateTime - this->getUpdateTime();
	quint64 x_readBytes = 0, x_writeBytes = 0;

	DWORD dwRet;
	MIB_IFROW ifRow;	/* 32-bit counters */
	MIB_IF_ROW2	ifRow2;	/* 64-bit counters, supported since Windows Vista, Server 2008 */

	if (pGetIfEntry2) {
		memset(&ifRow2, 0x0, sizeof(MIB_IF_ROW2));
		ifRow2.InterfaceLuid.Value = 0;
		ifRow2.InterfaceIndex = ifIndex;
		if ((dwRet = pGetIfEntry2(&ifRow2)) != NO_ERROR)
			qDebug() << "GetIfEntry2 failed with error: " << dwRet;
	} else {
		memset(&ifRow, 0x0, sizeof(MIB_IFROW));
		ifRow.dwIndex = ifIndex;
		if ((dwRet = GetIfEntry(&ifRow)) != NO_ERROR)
			qDebug() << "GetIfEntry failed with error: " << dwRet;
	}

	if (dwRet == NO_ERROR && time_interval > 0) {
		x_readBytes = pGetIfEntry2 ? ifRow2.InOctets : ifRow.dwInOctets;
		x_writeBytes = pGetIfEntry2 ? ifRow2.OutOctets : ifRow.dwOutOctets;
	}

	if (time_interval != 0 && (x_readBytes != 0 || x_writeBytes != 0)) {
		// 调整收发字节数
		x_readBytes -= baseStats.readBytes;
		x_writeBytes -= baseStats.writeBytes;

		// 更新时间
		this->updateTime = x_updateTime;

		// 计算速度
		if (x_readBytes < this->readBytes)	// 收计数器溢出
			x_readBytes += this->readBytes;
		if (x_writeBytes < this->writeBytes)	// 发计数器溢出
			x_writeBytes += this->writeBytes;

		this->recvSpeed = (x_readBytes - this->readBytes) / (time_interval / 1000.0f) / 1024.0f;
		this->sentSpeed = (x_writeBytes - this->writeBytes) / (time_interval / 1000.0f) / 1024.0f;

		// 更新流量
		this->readBytes = x_readBytes;
		this->writeBytes = x_writeBytes;
	}
}

#else
void VPNStatistics::updateByteCount(const QString& ifName, const QDateTime& updateTime,
		const VPNStatistics& baseStats)
{
	quint64 x_updateTime = updateTime.toMSecsSinceEpoch();
	quint64 time_interval = x_updateTime - this->getUpdateTime();
	quint64 x_readBytes = 0, x_writeBytes = 0;
	net_stat_t result;

	if (get_net_stat(qPrintable(ifName), &result)) {
		x_readBytes = result.ibytes;
		x_writeBytes = result.obytes;
	}

	if (time_interval != 0 && (x_readBytes != 0 || x_writeBytes != 0)) {
		// 调整收发字节数
		x_readBytes -= baseStats.readBytes;
		x_writeBytes -= baseStats.writeBytes;

		// 更新时间
		this->updateTime = x_updateTime;

		// 计算速度
		if (x_readBytes < this->readBytes)	// 收计数器溢出
			x_readBytes += this->readBytes;
		if (x_writeBytes < this->writeBytes)	// 发计数器溢出
			x_writeBytes += this->writeBytes;

		this->recvSpeed = (x_readBytes - this->readBytes) / (time_interval / 1000.0f) / 1024.0f;
		this->sentSpeed = (x_writeBytes - this->writeBytes) / (time_interval / 1000.0f) / 1024.0f;

		// 更新流量
		this->readBytes = x_readBytes;
		this->writeBytes = x_writeBytes;
	}
}
#endif

bool VPNStatistics::isEmpty() const
{
	return updateTime == 0 && readBytes == 0 && writeBytes == 0;
}

void VPNStatistics::clear()
{
	updateTime = 0;
	recvSpeed = 0.0f;
	sentSpeed = 0.0f;
	readBytes = 0;
	writeBytes = 0;
}

quint64 VPNStatistics::getUpdateTime() const
{
	return updateTime;
}

void VPNStatistics::setUpdateTime(quint64 updateTime)
{
	this->updateTime = updateTime;
}

float VPNStatistics::getRecvSpeed() const
{
	return recvSpeed;
}

float VPNStatistics::getSentSpeed() const
{
	return sentSpeed;
}

quint64 VPNStatistics::getReadBytes() const
{
	return readBytes;
}

void VPNStatistics::setReadBytes(quint64 readBytes)
{
	this->readBytes = readBytes;
}

quint64 VPNStatistics::getWriteBytes() const
{
	return writeBytes;
}

void VPNStatistics::setWriteBytes(quint64 writeBytes)
{
	this->writeBytes = writeBytes;
}

QDataStream& operator<<(QDataStream& stream, const VPNStatistics& stats)
{
	stream << VPNStatistics::serial_uid << stats.updateTime << stats.recvSpeed << stats.sentSpeed
		<< stats.readBytes << stats.writeBytes;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, VPNStatistics& stats)
{
	unsigned int local_serial_uid;

	stream >> local_serial_uid >> stats.updateTime >> stats.recvSpeed >> stats.sentSpeed
		>> stats.readBytes >> stats.writeBytes;

	Q_ASSERT(VPNStatistics::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}
