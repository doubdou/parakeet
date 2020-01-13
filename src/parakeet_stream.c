#include "parakeet_config.h"
#include "parakeet_stream.h"
#include "parakeet_buffer.h"

static parakeet_stream_manager_t * stream_globals = 0;

static char *RECORD_FMT_NAMES[] = {
	"native",
	"normal",
	"stereo",
	NULL
};

static inline int get_record_format(const char* format)
{
    int fmt = -1;
    int i = 0;
	for(i = 0; i < sizeof(RECORD_FMT_NAMES)/sizeof(char*) - 1; i ++)
	{
	    if(!strcasecmp(format, RECORD_FMT_NAMES[i])){
			fmt = i;
            break;
	    }
	}
    return fmt;
}


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
	int val = 0;

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
	//录音格式
	if(parakeet_get_config()->record_format == NULL)
	{
	    dzlog_error("Parakeet stream manager initialized fail: config record_format not found.");
		err = PARAKEET_FAIL;
		goto done;
	}

	val = get_record_format(parakeet_get_config()->record_format);
	if(val < 0)
	{
		dzlog_error("Parakeet stream manager initialized fail: config record_format invalid(%s).", parakeet_get_config()->record_format);
		err = PARAKEET_FAIL;
		goto done;   
	}

	stream_globals->record_fmt = (parakeet_record_fmt_t)val;

	dzlog_notice("Parakeet stream manager initialized.");

done:
    return err;
}

parakeet_errcode_t parakeet_stream_create(const char* callid, enum session_direction_t direct, 
                                              apr_port_t caller_port, apr_port_t callee_port, uint8_t pt)
{
	parakeet_errcode_t err = PARAKEET_OK;
    parakeet_stream_t * stream;
	parakeet_record_helper_t * rh;
	apr_pool_t * pool;
	char * in_path = NULL;
	char * out_path = NULL;
	char * audio_path = NULL;
	apr_threadattr_t *thd_attr = NULL;
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

	//缓存
	parakeet_buffer_create_dynamic(pool, &stream->raw_buffer_in, PARAKEET_BUFFER_BLOCKSIZE, PARAKEET_BUFFER_SIZE, 0);
	parakeet_buffer_create_dynamic(pool, &stream->raw_buffer_out, PARAKEET_BUFFER_BLOCKSIZE, PARAKEET_BUFFER_SIZE, 0);

	// 锁
	apr_thread_mutex_create(&stream->mutex, APR_THREAD_MUTEX_NESTED, pool);
	apr_thread_mutex_lock(stream->mutex);

	// stream是否已经存在 map处理上需要互斥开.
	apr_thread_rwlock_wrlock(stream_globals->map_lock);
	if (NULL == stream_globals->streams[local_port])
	{
		// 不存在, 则添加, 且可以继续执行.
		stream_globals->streams[local_port] = stream;
		dzlog_notice("debug==== parakeet_stream_create success callid: %s local_port:%d", callid, local_port);
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

	rh = apr_pcalloc(pool, sizeof(parakeet_record_helper_t));

    assert(rh);

    rh->pool = pool;
	if(stream_globals->record_fmt = PARAKEET_RECORD_FMT_STEREO)
	{
	    parakeet_set_flag(rh, PMSF_STEREO);
	}else if(stream_globals->record_fmt = PARAKEET_RECORD_FMT_NORMAL)
	{
	    parakeet_set_flag(rh, PMSF_NORMAL);
	}else {
		parakeet_set_flag(rh, PMSF_NATIVE);
	}

	if(parakeet_test_flag(rh, PMSF_NATIVE)){
        in_path = apr_psprintf(stream->pool, "../var/%s-%u-%u-in.%s", callid, caller_port, callee_port, get_audio_codec_name(pt));
	    out_path = apr_psprintf(stream->pool, "../var/%s-%u-%u-out.%s", callid, caller_port, callee_port, get_audio_codec_name(pt));
	    rh->fp_raw_in = fopen(in_path, "a+");
	    rh->fp_raw_out = fopen(out_path, "a+");

	    dzlog_notice("=== debug === native parakeet_stream_create callid: %s inpath %s ", callid, in_path);
	    dzlog_notice("=== debug === native parakeet_stream_create callid: %s outpath %s ", callid, out_path);
	}else {
		
		audio_path = apr_psprintf(stream->pool, "../var/%s-%u-%u.wav", callid, caller_port, callee_port);
		rh->fp = fopen(audio_path, "a+");
		dzlog_notice("=== debug === audio parakeet_stream_create callid: %s path:%s ", callid, audio_path);
	}

	parakeet_set_flag(rh, PMSF_FILE_OPEN);

	apr_threadattr_create(&thd_attr, pool);
	//线程栈大小系统默认为8M，8192 * 1024byte
	//可调优 240* 1024 byte
	//apr_threadattr_stacksize_set(thd_attr, 240 * 1024);
	apr_thread_create(&rh->thread, thd_attr, recording_thread, stream->rh, pool);

	stream->rh = rh;

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



static void *APR_THREAD_FUNC recording_thread(apr_thread_t *thread, void *obj)
{
	parakeet_record_helper_t *rh = (parakeet_record_helper_t *) obj;
	apr_size_t bsize = PARAKEET_RECOMMENDED_BUFFER_SIZE, samples = 0, inuse = 0;
	unsigned char *data;
	int channels = 1;

	parakeet_buffer_create_dynamic(&rh->audio_buffer, 1024 * 512, 1024 * 64, 0);
	rh->thread_ready = 1;

	channels = (stream_globals->record_fmt == PARAKEET_RECORD_FMT_STEREO) ? 2 : 1;
	data = apr_pcalloc(rh->pool, PARAKEET_RECOMMENDED_BUFFER_SIZE);

	while(parakeet_test_flag(rh->flags, PMSF_FILE_OPEN)) {
		
		apr_thread_mutex_lock(rh->audio_buffer_mtx);
		inuse = parakeet_buffer_inuse(rh->audio_buffer);

		if (rh->thread_ready && switch_channel_up_nosig(channel) && inuse < bsize) {
			apr_thread_mutex_unlock(rh->audio_buffer_mtx);
			apr_sleep(20000);
			continue;
		} else if ((!rh->thread_ready || switch_channel_down_nosig(channel)) && !inuse) {
			apr_thread_mutex_unlock(rh->audio_buffer_mtx);
			break;
		}

		samples = parakeet_buffer_read(rh->audio_buffer, data, bsize) / 2 / channels;
		switch_mutex_unlock(rh->buffer_mutex);

		if (switch_core_file_write(rh->fh, data, &samples) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error writing %s\n", rh->file);
			/* File write failed */
			set_completion_cause(rh, "uri-failure");
			if (rh->hangup_on_error) {
				switch_channel_hangup(channel, SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
				switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);
			}
		}
	}

	switch_core_session_rwunlock(session);

	return NULL;
}


