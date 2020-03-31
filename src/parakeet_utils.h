#ifndef PARAKEET_UTILS_H
#define PARAKEET_UTILS_H

#ifdef _DEBUG
#define TRACE	dzlog_info
#else
#define TRACE	if(0) printf
#endif

#include <stdio.h>
#include <stdlib.h>

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

#include "parakeet_types.h"
#include "parakeet_com.h"

#include <mysql/mysql.h>

#ifdef _WIN32
#include <cJSON.h>
#include <zlog/zlog.h>
#else
#include "../cJSON/cJSON.h"
#include <zlog.h>
#endif

#include "../liblua5.2/lua.h"
#include "../liblua5.2/lualib.h"
#include "../liblua5.2/lapi.h"
#include "../liblua5.2/lauxlib.h"

#include "../libfranksip/sip_message.h"
#include "../libfranksip/sdp_message.h"

#ifdef _WIN32
#include <Windows.h>
#pragma warning(disable: 4996)
#else
#include <unistd.h>
#endif

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#define parakeet_normalize_to_16bit(n) if (n > PARAKEET_SMAX) n = PARAKEET_SMAX; else if (n < PARAKEET_SMIN) n = PARAKEET_SMIN;

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
  \brief Set a flag on an arbitrary object while locked
  \param obj the object to set the flags on
  \param flag the or'd list of flags to set
*/
#define parakeet_set_flag_locked(obj, flag) assert((obj)->flag_mutex != NULL); \
apr_thread_mutex_lock((obj)->flag_mutex);								\
(obj)->flags |= (flag);\
apr_thread_mutex_unlock((obj)->flag_mutex);

/*!
  \brief Clear a flag on an arbitrary object
  \param obj the object to test
  \param flag the or'd list of flags to clear
*/
#define parakeet_clear_flag_locked(obj, flag) apr_thread_mutex_lock((obj)->flag_mutex); (obj)->flags &= ~(flag); apr_thread_mutex_unlock((obj)->flag_mutex);


/*!
  \brief Clear a flag on an arbitrary object while locked
  \param obj the object to test
  \param flag the or'd list of flags to clear
*/
#define parakeet_clear_flag(obj, flag) (obj)->flags &= ~(flag)


/*!
  \brief Free a pointer and set it to NULL unless it already is NULL
  \param it the pointer
*/
#define parakeet_safe_free(it) if (it) {free(it);it=NULL;}

/*!
  \brief Test for NULL or zero length string
  \param s the string to test
  \return true value if the string is NULL or zero length
*/
static inline int _zstr(const char *s)
{
	return !s || *s == '\0';
}

#define zstr(x)  _zstr(x)

typedef enum parakeet_errcode_e{
    PARAKEET_STATUS_OK,
	PARAKEET_STATUS_FAIL,
	PARAKEET_STATUS_MEMERR,
	PARAKEET_STATUS_TIMEOUT,
	PARAKEET_STATUS_PARAM_INVALID,
	PARAKEET_STATUS_INTR,
	PARAKEET_STATUS_INUSE,
	PARAKEET_STATUS_NOT_EXIST,
	PARAKEET_STATUS_SOCKERR,
	PARAKEET_STATUS_BREAK,
	PARAKEET_STATUS_TERM,
	PARAKEET_STATUS_GENERR,
	PARAKEET_STATUS_DATA_ERROR,
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

