#ifndef __CONFIG_H__
#define __CONFIG_H__

/*
 * ͷ�ļ���Դ�ļ���Ҫ������ļ��������, ���ﶨ��ĺ�����д��붼��Ч���������õĵ���������
 */

/*
 * !!����ԭ��!! ��Чֻ�ǲ����ù���, ���뻹�Ǳ��������
 * ĿǰENABLE_GUOMI����(��Ҫ֧�ֹٷ�������OpenSSL��������˷����Ĺ���OpenSSL��)
 *
 * !!��ͬ�ķ���, �����ļ����໥����!!
 * ���շ�����ENCRYPT_DEVICE_TOOL��VPN_PROCESS������, ��������Ӧ�ö�һ��(���й����豸��ش���
 * ���Ƶ�ENCRYPT_DEVICE_TOOL��VPN_PROCESS����); VPN_CLIENT, VPN_SERVICE�������й����豸���
 * ����
 */

/* ��Ч�����㷨֧�� */
//#define ENABLE_GUOMI

#define ENABLE_INTEGRATION

/* ���ø���ģ�� */
//#define ENABLE_UPDATER

/* ���û�����¡֧��(������ֿ�¡, �Զ���װTAP����) */
#ifdef _WIN32
#define ENABLE_CLONE
#endif

/* ������������ʵ�� */
#define ENABLE_VENDOR_COMPATIBLE

#ifdef _WIN32
#ifndef _DEBUG
#define ENABLE_MINI_DUMP
#endif
#endif

#ifdef _WIN32
#pragma warning(disable: 4834 26812)
#endif

#endif