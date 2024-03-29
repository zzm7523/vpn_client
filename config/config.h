#ifndef __CONFIG_H__
#define __CONFIG_H__

/*
 * 头文件和源文件都要把这个文件放在最顶部, 这里定义的宏对所有代码都生效包括被引用的第三方代码
 */

/*
 * !!编码原则!! 无效只是不启用功能, 代码还是编译进程序
 * 目前ENABLE_GUOMI例外(需要支持官方发布的OpenSSL库和其他人发布的国密OpenSSL库)
 *
 * !!不同的发布, 配置文件能相互兼容!!
 * 最终发布除ENCRYPT_DEVICE_TOOL和VPN_PROCESS程序外, 其它程序应该都一样(所有国密设备相关代码
 * 都移到ENCRYPT_DEVICE_TOOL和VPN_PROCESS程序); VPN_CLIENT, VPN_SERVICE程序不再有国密设备相关
 * 代码
 */

/* 有效国密算法支持 */
//#define ENABLE_GUOMI

#define ENABLE_INTEGRATION

/* 启用更新模块 */
//#define ENABLE_UPDATER

/* 启用机器克隆支持(如果发现克隆, 自动重装TAP驱动) */
#ifdef _WIN32
#define ENABLE_CLONE
#endif

/* 兼容其它厂商实现 */
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
