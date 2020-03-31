/***************************************************************************
 * HTTP Server                                                             *
 *                                                                         *
 * 本文件是SIP Proxy服务的一部分                                                     *
 *                                                                         *
 * 版权信息    　　                                                              *
 *                                                                         *
 * @file	parakeet_http.h                                                *
 * @brief	REST接口处理                                                       *
 * 本程序处理各种HTTP请求, 包括网关,路由组,路由规则的增删改查                                       *
 * 操作已被简化, 大量操作被移除                                                         *
 *                                                                         *
 * @author	jinzhuwei                                                      * 
 * @email	jinzw_programmer@163.com                                       *
 * @version	1.0.0.1                                                        *
 * @date	2018-11-22                                                     *
 * @license                                                                *
 *                                                                         *
 *-------------------------------------------------------------------------*
 * Remark                                                                  *
 *-------------------------------------------------------------------------*
 * Change history                                                          *
 * date		  | version | author       | description                       *
 *-------------------------------------------------------------------------*
 * 2018-11-22 | 1.0.0.1 | jin zhuwei   | 创建                                *
 *-------------------------------------------------------------------------*
 *                                                                         *
 **************************************************************************/

#ifndef PARAKEET_LUA_HTTP_H
#define PARAKEET_LUA_HTTP_H

#include "parakeet_utils.h"

#define HTTP_PREFIX_PARAKEET	"/sip"
#define HTTP_PREFIX_AAA "/aaa"

/**
 * @brief 启动HTTP Server
 * 由于HTTP请求不会很多, 所以当前以单线程方式启动HTTP Server
 * 启动成功后, 任何请求消息都会触发 generic_handler 回调函数
 * @param port	HTTP服务的监听端口.
 *
 * @return 返回说明
 *     -<em>-1</em> 初始化失败
 *     -<em>0</em> 初始化成功
 */
int  parakeet_luahttp_initialize(apr_pool_t * pool, int port);

// 停止parakeet服务.
void parakeet_luahttp_destroy(void);


#endif
