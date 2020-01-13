#ifndef PARAKEET_UTILS_H
#define PARAKEET_UTILS_H

#ifdef _DEBUG
#define TRACE	dzlog_info
#else
#define TRACE	if(0) printf
#endif

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
#include "../libfranksip/sdp_message.h"

/* size of the buffer */
#define PARAKEET_BUFFER_SIZE       (1024 * 64)
#define PARAKEET_BUFFER_BLOCKSIZE  (1024 * 512)
#define PARAKEET_BYTES_PER_SAMPLE  (2)	      /* 2 bytes per sample */

#define PARAKEET_RECOMMENDED_BUFFER_SIZE (8192)

/*!
  \brief Test for the existance of a flag on an arbitary object
  \param obj the object to test
  \param flag the or'd list of flags to test
  \return true value if the object has the flags defined
*/
#define parakeet_test_flag(obj, flag) ((obj)->flags & flag)

/*!
  \brief Set a flag on an arbitrary object
  \param obj the object to set the flags on
  \param flag the or'd list of flags to set
*/
#define parakeet_set_flag(obj, flag) (obj)->flags |= (flag)


/*!
  \brief Free a pointer and set it to NULL unless it already is NULL
  \param it the pointer
*/
#define parakeet_safe_free(it) if (it) {free(it);it=NULL;}


typedef enum parakeet_errcode_e{
    PARAKEET_OK,
	PARAKEET_FAIL,
	PARAKEET_MEMERR,
	PARAKEET_TIMEOUT,
	PARAKEET_PARAM_INVALID,
	PARAKEET_INTR,
	PARAKEET_INUSE,
	PARAKEET_NOT_EXIST,
	PARAKEET_SOCKERR,
	PARAKEET_BREAK,
	PARAKEET_TERM,
	PARAKEET_DATA_ERROR,
}parakeet_errcode_t;

#define DIR_STR_INCOMING	"incoming"
#define DIR_STR_OUTGOING	"outgoing"
#define DIR_STR_BOTH		"both"

typedef enum packet_direction_e
{
	// 包的方向
	PKT_DIRECT_ANY=0,
	PKT_DIRECT_INCOMING, //收到
	PKT_DIRECT_OUTGOING, //送出
}packet_direction_t;


#endif

