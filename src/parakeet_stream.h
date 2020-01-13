#ifndef PARAKEET_STREAM_H
#define PARAKEET_STREAM_H

#include "parakeet_config.h"
#include "parakeet_buffer.h"
#include "parakeet_session.h"
#include "parakeet_com.h"


typedef enum{
    PARAKEET_RECORD_FMT_NATIVE,
    PARAKEET_RECORD_FMT_NORMAL,
    PARAKEET_RECORD_FMT_STEREO
}parakeet_record_fmt_t;

typedef struct parakeet_record_helper_t parakeet_record_helper_t;

struct parakeet_record_helper_t{
	apr_pool_t * pool;				    ///< 内存池
    parakeet_buffer_t* audio_buffer;
	apr_thread_mutex_t * audio_buffer_mtx;		
	apr_uint32_t flags;

    FILE * fp_raw_in;                ///< native in
    FILE * fp_raw_out;               ///< native out 
    FILE * fp;                       ///< wav 
    
	apr_thread_t *thread;
    int thread_ready;
};

typedef struct parakeet_stream_t parakeet_stream_t;

struct parakeet_stream_t{
	apr_pool_t * pool;				    ///< 保存信息的内存池, 每条媒体使用独立的内存池.
    char * callid;                      ///< 媒体通道所属会话的callid
    apr_thread_mutex_t * mutex;		    ///< 互斥锁
    uint8_t pt;                         ///< 有效负载类型
    rtp_header_t* last_rtp_hdr;         ///< 前回rtp头域
    apr_port_t remote_port;             ///< 远端媒体端口
    
    parakeet_buffer_t * raw_buffer_in;  ///< 原始数据缓存
    parakeet_buffer_t * raw_buffer_out; ///< 原始数据缓存
               
    parakeet_record_helper_t* rh;       
};

typedef struct parakeet_stream_manager_t parakeet_stream_manager_t;

struct parakeet_stream_manager_t
{
	apr_pool_t * pool;				       ///< 内存池.
    parakeet_stream_t * streams[65536];    ///< 保存所有媒体数据流信息. 数据面操作最多的数据.以本地端口为索引
    apr_thread_rwlock_t * map_lock;	       ///< 对map加锁
    parakeet_record_fmt_t * record_fmt;    ///< 录音格式
    //uint32_t sum_of_streams;              ///< 活跃的媒体流数量
};


typedef enum {
	PMSF_BOTH = 0,
	PMSF_READ_STREAM = (1 << 0),
	PMSF_WRITE_STREAM = (1 << 1),
	PMSF_STEREO = (1 << 5),
	PMSF_NORMAL = (1 << 6),
	PMSF_NATIVE = (1 << 7),
	PMSF_FILE_OPEN = (1 << 8),
	PMSF_FILE_CLOSE = (1 << 9)
} parakeet_media_stream_flag_enum_t;
	
typedef uint32_t parakeet_media_stream_flag_enum_t;

parakeet_errcode_t parakeet_stream_factory_init(apr_pool_t * pool);

parakeet_errcode_t parakeet_stream_create(const char* callid, enum session_direction_t direct, 
                                              apr_port_t caller_port, apr_port_t callee_port, uint8_t pt);

parakeet_stream_t * parakeet_stream_locate(const apr_port_t port);

void parakeet_stream_unlock(parakeet_stream_t * stream);

#endif