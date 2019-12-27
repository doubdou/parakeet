#include "parakeet_config.h"
#include "parakeet_stream.h"
#include "parakeet_buffer.h"

static parakeet_stream_manager_t * stream_globals = 0;

static inline char *get_audio_codec_name(uint8_t audio_type)
{
	switch (audio_type) {
		case PT_PCMU:
			return "PCMU";
		case PT_G723:
			return "G723";
		case PT_PCMA:
			return "PCMA";
		case PT_G722:
			return "G722";
		case PT_L16_2:
			return "L16";
		case PT_L16_1:
			return "L16";
		case PT_G729:
			return "G729";
		case PT_RFC2833:
			return "telephone-event";
		default:
			return NULL;
	}
}

parakeet_errcode_t parakeet_stream_factory_init(apr_pool_t * pool)
{
    parakeet_errcode_t err = PARAKEET_OK;

	dzlog_notice("initializing stream manager...");

	stream_globals = apr_pcalloc(pool, sizeof(*stream_globals));

	//内存池创建
	apr_pool_create(&stream_globals->pool, pool);

    //媒体流表
	memset(stream_globals->streams, 0x0, sizeof(stream_globals->streams));
	
	// 读写锁
	apr_thread_rwlock_create(&stream_globals->map_lock, pool);

	//内存池创建
	apr_pool_create(&stream_globals->pool, pool);	

	// 读写锁
	//apr_thread_rwlock_create(&stream_globals->stream_lock, pool);
	
    return err;
}

parakeet_errcode_t parakeet_stream_create(const char* callid, enum session_direction_t direct, 
                                              apr_port_t caller_port, apr_port_t callee_port, uint8_t pt)
{
	parakeet_errcode_t err = PARAKEET_OK;
    parakeet_stream_t * stream;
	apr_pool_t * pool;
	char * in_path = NULL;
	char * out_path = NULL;
	apr_port_t local_port;
	apr_port_t remote_port;
	int rv = -1;

	/**
	* 根据呼叫方向、主被叫媒体端口，唯一确认本地端口和远端端口
	* 呼入   caller_port --> 远端端口 --> remote_port
	*      callee_port --> 本地端口 -->     表的索引 
	*
	* 呼出 caller_port --> 本地端口 --> 表的索引 
	*      callee_port --> 远端端口 --> remote_port
	*/

	if(direct == DIR_TYPE_INCOMING)
	{
	   local_port = callee_port;
	   remote_port = caller_port;
	}else {
	   local_port = caller_port;
	   remote_port = callee_port;
	}
	
	dzlog_notice("debug==== parakeet_stream_create start  callid: %s pt:%u", callid, pt);

	// 创建会话.
	apr_pool_create(&pool, 0);
	stream = apr_pcalloc(pool, sizeof(parakeet_stream_t));

	assert(stream);

	stream->pool = pool;
	stream->callid = apr_pstrdup(pool, callid);
	stream->pt = pt;
	stream->remote_port = remote_port;
	stream->buffer = parakeet_buffer_create(pool);

	// 锁
	apr_thread_mutex_create(&stream->mutex, APR_THREAD_MUTEX_DEFAULT, pool);
	apr_thread_mutex_lock(stream->mutex);

	// stream是否已经存在.
	// map处理上需要互斥开.
	apr_thread_rwlock_wrlock(stream_globals->map_lock);
	if (NULL == stream_globals->streams[local_port])
	{
		// 不存在, 则添加, 且可以继续执行.
		stream_globals->streams[local_port] = stream;
		dzlog_notice("debug==== parakeet_stream_create success  callid: %s local_port:%d", callid, local_port);
		rv = 0;
	}
	apr_thread_rwlock_unlock(stream_globals->map_lock);

	if (0 != rv)
	{
		apr_thread_mutex_unlock(stream->mutex);
		apr_thread_mutex_destroy(stream->mutex);
		apr_pool_destroy(stream->pool);

		err = PARAKEET_INUSE;
		goto done;
	}

    /**
	* 录音
	* 原始文件 区分通道方向 in / out
	* wav文件   区分单/双声道
	*/
    in_path = apr_psprintf(stream->pool, "../var/%s-%u-%u-in.%s", callid, caller_port, callee_port, get_audio_codec_name(pt));
	out_path = apr_psprintf(stream->pool, "../var/%s-%u-%u-out.%s", callid, caller_port, callee_port, get_audio_codec_name(pt));
	stream->audio_in = fopen(in_path, "a+");
	stream->audio_out = fopen(out_path, "a+");

	dzlog_notice("debug==== parakeet_stream_create  callid: %s inpath %s ", callid, in_path);
	dzlog_notice("debug==== parakeet_stream_create	callid: %s outpath %s ", callid, out_path);

	parakeet_stream_unlock(stream);

done:
	return err;
}

parakeet_stream_t * parakeet_stream_locate(const apr_port_t port)
{
	// 根据local port 查找流且加锁
	parakeet_stream_t * stream = 0;
	dzlog_notice("debug==== parakeet_stream_locate	local_port:%u ", port);

	apr_thread_rwlock_rdlock(stream_globals->map_lock);
    stream = stream_globals->streams[port];
    if(stream)
    {
        apr_thread_mutex_lock(stream->mutex);
    }
	apr_thread_rwlock_unlock(stream_globals->map_lock);
	
	return stream;
}

void parakeet_stream_unlock(parakeet_stream_t * stream)
{
	assert(stream);
	apr_thread_mutex_unlock(stream->mutex);
}


