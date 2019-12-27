#ifndef PARAKEET_STREAM_H
#define PARAKEET_STREAM_H

#include "parakeet_config.h"
#include "parakeet_buffer.h"
#include "parakeet_session.h"
#include "parakeet_com.h"

typedef struct parakeet_stream_t parakeet_stream_t;

struct parakeet_stream_t{
	apr_pool_t * pool;				  ///< 保存信息的内存池, 每条媒体使用独立的内存池.
    char * callid;                    ///< 媒体通道所属会话的callid
    uint8_t pt;                       ///< 有效负载类型
    apr_port_t remote_port;           ///< 远端媒体端口
    parakeet_buffer_t * buffer;       ///< 数据缓存
    apr_thread_mutex_t * mutex;		  ///< 对流数据的互斥锁
    FILE * audio_in;                  ///< 录音文件描述符 
    FILE * audio_out;                 ///< 录音文件描述符                        
};

typedef struct parakeet_stream_manager_t parakeet_stream_manager_t;

struct parakeet_stream_manager_t
{
	apr_pool_t * pool;				      ///< 内存池.
    parakeet_stream_t * streams[65536];   ///< 保存所有媒体数据流信息. 数据面操作最多的数据.以本地端口为索引
    apr_thread_rwlock_t * map_lock;	      ///< 对map加锁
    //uint32_t sum_of_streams;              ///< 活跃的媒体流数量
};

parakeet_errcode_t parakeet_stream_factory_init(apr_pool_t * pool);

parakeet_errcode_t parakeet_stream_create(const char* callid, enum session_direction_t direct, 
                                              apr_port_t caller_port, apr_port_t callee_port, uint8_t pt);

parakeet_stream_t * parakeet_stream_locate(const apr_port_t port);

void parakeet_stream_unlock(parakeet_stream_t * stream);

#endif