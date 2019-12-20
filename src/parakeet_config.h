#ifndef PARAKEET_CONFIG_H
#define PARAKEET_CONFIG_H

#include <zlog.h>
#include "parakeet_utils.h"
#include <assert.h>

// 基本配置
typedef struct parakeet_global_config_t	parakeet_global_config_t;
struct parakeet_global_config_t
{
	apr_port_t		port;			///< sip端口
	apr_uint32_t	thread_number;	///< 线程数
	apr_uint32_t	max_sessions;	///< 最大会话数

	apr_port_t		http_port;		///< http端口,默认1080
	apr_uint32_t	call_timeout;	///< 呼叫的超时时间(秒)
	apr_uint32_t	call_limit;		///< 会话超时时间(最长通话时间)
	apr_uint32_t	login_timeout;	///< 登录后超时时间(秒钟

	const char *	notify_url;	///< 事件通知的URL

	apr_byte_t		cdr_enable;		///< 是否需要写话单
//	apr_byte_t		rport;			///< 是否支持rport 默认支持, 无需设置

	const char *	lan;			///< 内网IP, 该地址必须配置准确.
	const char *	wan;			///< 公网IP, 配置或自动猜测

	const char *    nic;		    ///< 网卡设备名

	const char *	db_host;		///< MySQL数据库IP地址
	const char *	db_name;		///< MySQL数据库名称, 默认siproxy
	const char *	db_user;		///< MySQL数据库登录账号, 默认root
	const char *	db_password;	///< MySQL数据库登录密码, 默认root
	apr_port_t		db_port;		///< MySQL数据库服务器端口, 默认3306
};

parakeet_errcode_t parakeet_config_load(apr_pool_t * pool);


// 获取配置句柄
parakeet_global_config_t * parakeet_get_config(void);

#endif






