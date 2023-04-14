#include <QByteArray>
#include <QDebug>

#include "policy_engine_i.h"
#include "policy.h"
#include "terminal_bind_policy.h"
#include "password_policy.h"
#include "update_policy.h"
#include "resource_policy.h"
#include "cluster_policy.h"

QMutex PolicyEngineI::globalPolicysMutex;
QMap<QString, PolicyFactory*> PolicyEngineI::globalPolicyFactorys;

const unsigned int ApplyResult::serial_uid = 0x047;

const QString ApplyResult::TYPE_NAME = QLatin1String("type_name");
const QString ApplyResult::CLUSTER_ALGORITHM = QLatin1String("cluster_algorithm");
const QString ApplyResult::SERVER_ENDPOINT_LIST = QLatin1String("server_endpoint_list");
const QString ApplyResult::SERVICE_URL = QLatin1String("service_url");
const QString ApplyResult::WEAK_PASSWORD = QLatin1String("weak_password");
const QString ApplyResult::ACCESSIBLE_RESOURCE = QLatin1String("accessible_resource");

static char** alloc_string_array(const int array_len, const int max_string_len)
{
	char **string_array = (char**) malloc (array_len * sizeof (char*));
	if (string_array)
	{
		int i;
		for (i = 0; i < array_len; ++i)
		{
			string_array[i] = (char*) malloc (max_string_len + 1);
			if (string_array[i])
				memset (string_array[i], 0x0, max_string_len + 1);
		}
	}
	return string_array;
}

static void free_string_array(char **string_array, const int array_len)
{
	if (string_array)
	{
		int i;
		for (i = 0; i < array_len; ++i)
			if (string_array[i])
				free (string_array[i]);
		free (string_array);
	}
}

static inline bool is_space(unsigned char c)
{
	return c == '\0' || isspace (c);
}

static int parse_line(const char *line, bool dotbackslash, char **string_array, int *array_len, const int max_string_len)
{
	const int STATE_INITIAL = 0;
	const int STATE_READING_QUOTED_PARM = 1;
	const int STATE_READING_UNQUOTED_PARM = 2;
	const int STATE_DONE = 3;
	const int STATE_READING_SQUOTED_PARM = 4;

	int ret = 0, out_array_len = 0;
	const char *c = line;
	int state = STATE_INITIAL;
	bool backslash = false;
	char in, out;

	char *param = (char*) malloc (max_string_len);
	int param_len = 0;

	do {
		in = *c;
		out = 0;

		if (!backslash && in == '\\' && state != STATE_READING_SQUOTED_PARM) {
			if (!dotbackslash)
				backslash = true;
			else
				out = in;
		} else {
			if (state == STATE_INITIAL) {
				if (!is_space (in)) {
					if (in == ';' || in == '#') /* comment */
						break;
					if (!backslash && in == '\"')
						state = STATE_READING_QUOTED_PARM;
					else if (!backslash && in == '\'')
						state = STATE_READING_SQUOTED_PARM;
					else {
						out = in;
						state = STATE_READING_UNQUOTED_PARM;
					}
				}
			} else if (state == STATE_READING_UNQUOTED_PARM) {
				if (!backslash && is_space (in))
					state = STATE_DONE;
				else
					out = in;
			} else if (state == STATE_READING_QUOTED_PARM) {
				if (!backslash && in == '\"')
					state = STATE_DONE;
				else
					out = in;
			} else if (state == STATE_READING_SQUOTED_PARM) {
				if (in == '\'')
					state = STATE_DONE;
				else
					out = in;
			}
			if (state == STATE_DONE) {
				/* ASSERT (parm_len > 0); */
				memcpy (string_array[out_array_len], param, param_len);
				string_array[out_array_len][param_len] = '\0';
				state = STATE_INITIAL;
				param_len = 0;
				++out_array_len;
			}

			if (backslash && out) {
				if (!(out == '\\' || out == '\"' || is_space (out)))
					goto finish;
			}
			backslash = false;
		}

		/* store parameter character */
		if (out) {
			if (param_len >= max_string_len)
				goto finish;
			param[param_len++] = out;
		}

		/* avoid overflow if too many parms in one config file line */
		if (out_array_len >= *array_len)
			break;

	} while (*c++ != '\0');

	if (state == STATE_READING_QUOTED_PARM || state == STATE_READING_SQUOTED_PARM)
		goto finish;
	if (state != STATE_INITIAL)
		goto finish;

	ret = 1;
	*array_len = out_array_len;

finish:
	if (param)
		free (param);
	return ret;
}

void PolicyEngineI::registerFactory(const QString& objectType, PolicyFactory *factory)
{
	QMutexLocker locker(&globalPolicysMutex);
	if (!globalPolicyFactorys.contains(objectType))
		globalPolicyFactorys.insert(objectType, factory);
}

void PolicyEngineI::unregisterFactory(const QString& objectType)
{
	QMutexLocker locker(&globalPolicysMutex);
	globalPolicyFactorys.remove(objectType);
}

Policy* PolicyEngineI::newInstance(const QString& externalForm)
{
#define MAX_POLICY_ITEM	64
#define MAX_ITEM_LEN	512

	int array_len = MAX_POLICY_ITEM;
	char **string_array = alloc_string_array(array_len, MAX_ITEM_LEN);
	const QByteArray externalFormUtf8 = externalForm.toUtf8();
	QStringList items;

	// externalForm已经处理了\逃逸
	if (parse_line(externalFormUtf8.constData(), true, string_array, &array_len, MAX_ITEM_LEN)
			&& array_len > 0) {
		for (int i = 0; i < array_len; ++i)
			items.append(QString::fromUtf8(string_array[i]));
	}

	free_string_array(string_array, MAX_POLICY_ITEM);

	if (items.size() > 0) {
		QMutexLocker locker(&globalPolicysMutex);
		PolicyFactory *factory = globalPolicyFactorys.value(items.takeFirst());
		if (factory)
			return factory->newInstance(items);
	}

	qDebug() << "unknown policy " << externalForm;
	return NULL;
}

PolicyEngineI::PolicyEngineI()
{
	registerFactory(UpdatePolicy::type_name(), new GeneralPolicyFactory<UpdatePolicy>());
	registerFactory(PasswordPolicy::type_name(), new GeneralPolicyFactory<PasswordPolicy>());
	registerFactory(ClusterPolicy::type_name(), new GeneralPolicyFactory<ClusterPolicy>());
	registerFactory(ResourcePolicy::type_name(), new GeneralPolicyFactory<ResourcePolicy>());
	// 终端绑定是本地策略, 不能由服务端推送
//	registerFactory(TerminalBindPolicy::type_name(), new GeneralPolicyFactory<TerminalBindPolicy>());
}

QDataStream& operator<<(QDataStream& stream, const ApplyResult& applyResult)
{
	unsigned int result = static_cast<unsigned int>(applyResult.result);

	stream << ApplyResult::serial_uid << result << applyResult.reason << applyResult.attributes;
	return stream;
}

QDataStream& operator>>(QDataStream& stream, ApplyResult& applyResult)
{
	unsigned int local_serial_uid, result;

	stream >> local_serial_uid >> result >> applyResult.reason >> applyResult.attributes;
	applyResult.result = static_cast<ApplyResult::Result>(result);

	Q_ASSERT(ApplyResult::serial_uid == local_serial_uid || QDataStream::Ok != stream.status());
	return stream;
}
