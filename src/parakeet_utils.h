#ifndef PARAKEET_UTILS_H
#define PARAKEET_UTILS_H

#include <stdio.h>

// APR 库.
#include "apr-1/apr.h"
#include <apr-1/apr_env.h>
#include "apr-1/apr_general.h"
#include <apr-1/apr_atomic.h>
#include <apr-1/apr_thread_proc.h>		// 线程支持
#include <apr-1/apr_thread_mutex.h>		// 锁
#include <apr-1/apr_thread_rwlock.h>	// 读写锁
#include <apr-1/apr_thread_pool.h>		// 线程池
#include <apr-1/apr_thread_cond.h>		// 条件[]
#include <apr-1/apr_time.h>				// 时间
#include <apr-1/apr_network_io.h>		// 网络
#include <apr-1/apr_portable.h>			// 端口
#include <apr-1/apr_pools.h>			// 内存池
#include <apr-1/apr_signal.h>			// 信号
#include <apr-1/apr_hash.h>				// 哈希表
#include <apr-1/apr_strings.h>			// 字符串
#include <apr-1/apr_queue.h>			// 队列
#include <apr-1/apr_fnmatch.h>			// 字符串匹配
#include <apr-1/apr_xml.h>				// xml
#include <apr-1/apr_file_info.h>
#include <apr-1/apr_md5.h>
#include <apr-1/apr_uuid.h>


#include "../libfranksip/sip_message.h"


typedef enum parakeet_errcode_e{
    PARAKEET_OK,
	PARAKEET_FAIL,
	PARAKEET_MEMERR,
	PARAKEET_TIMEOUT,
	PARAKEET_PARAM_INVALID,
	PARAKEET_INTR,
	PARAKEET_INUSE,
	PARAKEET_SOCKERR,
	PARAKEET_BREAK,
	PARAKEET_TERM,
	PARAKEET_DATA_ERROR,
}parakeet_errcode_t;


#endif

