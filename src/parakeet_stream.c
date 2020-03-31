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
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
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
		err = PARAKEET_STATUS_FAIL;
		goto done;
	}

	val = get_record_format(parakeet_get_config()->record_format);
	if(val < 0)
	{
		dzlog_error("Parakeet stream manager initialized fail: config record_format invalid(%s).", parakeet_get_config()->record_format);
		err = PARAKEET_STATUS_FAIL;
		goto done;   
	}

	stream_globals->record_fmt = (parakeet_record_fmt_t)val;

	dzlog_notice("Parakeet stream manager initialized.");

done:
    return err;
}

parakeet_errcode_t parakeet_stream_get_codec_impl(parakeet_stream_t *stream, parakeet_codec_implementation_t *impl)
{
	if (stream->impl.codec_id) {
		*impl = stream->impl;
		return PARAKEET_STATUS_OK;
	}

	memset(impl, 0, sizeof(*impl));
	impl->number_of_channels = 1;
	return PARAKEET_STATUS_FAIL;
}

static void *APR_THREAD_FUNC recording_thread(apr_thread_t *thread, void *obj)
{
	//parakeet_record_helper_t *rh = (parakeet_record_helper_t *) obj;
	parakeet_media_bug_t *bug = (parakeet_media_bug_t *) obj;
	parakeet_record_helper_t *rh;
	apr_size_t bsize = PARAKEET_RECOMMENDED_BUFFER_SIZE, samples = 0, inuse = 0;
	unsigned char *data;
	int channels = 1;

	rh = parakeet_core_media_bug_get_user_data(bug);
	parakeet_buffer_create_dynamic(&rh->thread_buffer, 1024 * 512, 1024 * 64, 0);
	rh->thread_ready = 1;

	channels = (stream_globals->record_fmt == PARAKEET_RECORD_FMT_STEREO) ? 2 : 1;
	data = apr_pcalloc(rh->pool, PARAKEET_RECOMMENDED_BUFFER_SIZE);
	
	dzlog_debug("Recording thread created.\n");

	while(parakeet_test_flag(&rh->fh, PARAKEET_FILE_OPEN)) {
		
		apr_thread_mutex_lock(rh->buffer_mutex);
		inuse = parakeet_buffer_inuse(rh->thread_buffer);

		if (rh->thread_ready && inuse < bsize) {
			apr_thread_mutex_unlock(rh->buffer_mutex);
			apr_sleep(20000);
			continue;
		} 
	    else if (!rh->thread_ready && !inuse) {
			apr_thread_mutex_unlock(rh->buffer_mutex);
			break;
		}

		samples = parakeet_buffer_read(rh->thread_buffer, data, bsize) / 2 / channels;
		apr_thread_mutex_unlock(rh->buffer_mutex);

		if (parakeet_core_file_write(&rh->fh, data, &samples) != PARAKEET_STATUS_OK) {
			dzlog_error("Error writing %s\n", rh->file);
		}

		//fwrite(data, 1, samples, rh->fp);
	}

	return NULL;
}

static parakeet_bool_t record_callback(parakeet_media_bug_t *bug, void *user_data, parakeet_abc_type_t type)
{
	parakeet_stream_t *stream = parakeet_core_media_bug_get_stream(bug);
	//switch_channel_t *channel = switch_core_session_get_channel(session);
	parakeet_record_helper_t *rh = (parakeet_record_helper_t *) user_data;
	//switch_event_t *event;
	parakeet_frame_t *nframe;
	apr_size_t len = 0;
	//unsigned char null_data[PARAKEET_RECOMMENDED_BUFFER_SIZE] = {0};
	apr_pool_t *pool = stream->pool;

	switch (type) {
		case PARAKEET_ABC_TYPE_INIT:
		{
			apr_threadattr_t *thd_attr = NULL;
			
			int sanity = 200;

			parakeet_stream_get_codec_impl(stream, &rh->impl);
			apr_thread_mutex_create(&rh->buffer_mutex, APR_THREAD_MUTEX_NESTED, pool);
			apr_threadattr_create(&thd_attr, pool);
			apr_threadattr_stacksize_set(thd_attr, PARAKEET_THREAD_STACKSIZE);
			apr_thread_create(&rh->thread, thd_attr, recording_thread, bug, pool);

			while(--sanity > 0 && !rh->thread_ready) {
				apr_sleep(10000); //yield
			}
			dzlog_debug("Bugging initialized %s", rh->file);
		}
			break;
		case PARAKEET_ABC_TYPE_TAP_NATIVE_READ:
		{
			apr_time_t now = apr_time_now();
			apr_time_t diff;

			rh->rready = 1;

			nframe = parakeet_core_media_bug_get_native_read_frame(bug);
			len = nframe->datalen;

			if (!rh->wready) {
				unsigned char fill_data[PARAKEET_RECOMMENDED_BUFFER_SIZE] = {0};
				apr_size_t fill_len = len;
			    dzlog_debug("native read, write not ready.");

				parakeet_gen_encoded_silence(fill_data, &rh->impl, len);
				parakeet_core_file_write(&rh->out_fh, fill_data, &fill_len);
			}

			if (rh->last_read_time && rh->last_read_time < now) {
				diff = (now - rh->last_read_time) / rh->impl.microseconds_per_packet;

				if (diff > 3) {
					unsigned char fill_data[PARAKEET_RECOMMENDED_BUFFER_SIZE] = {0};
					parakeet_gen_encoded_silence(fill_data, &rh->impl, len);

					while(diff > 1) {
						apr_size_t fill_len = len;
						dzlog_debug("native read, diff(%ld)(fill_len:%lu).", diff, fill_len);
						parakeet_core_file_write(&rh->in_fh, fill_data, &fill_len);
						diff--;
					}
				}
			}

			parakeet_core_file_write(&rh->in_fh, nframe->data, &len);

			rh->last_read_time = now;
			rh->writes++;
		}
			break;
		case PARAKEET_ABC_TYPE_TAP_NATIVE_WRITE:
		{
			apr_time_t now = apr_time_now();
			apr_time_t diff;
			
			rh->wready = 1;

			nframe = parakeet_core_media_bug_get_native_write_frame(bug);
			len = nframe->datalen;

			if (!rh->rready) {
				unsigned char fill_data[PARAKEET_RECOMMENDED_BUFFER_SIZE] = {0};
				apr_size_t fill_len = len;
				parakeet_gen_encoded_silence(fill_data, &rh->impl, len);
				dzlog_debug("native write, read not ready.");
				parakeet_core_file_write(&rh->in_fh, fill_data, &fill_len);
			}
		
			if (rh->last_write_time && rh->last_write_time < now) {
				diff = (now - rh->last_write_time) / rh->impl.microseconds_per_packet;

				if (diff > 3) {
					unsigned char fill_data[PARAKEET_RECOMMENDED_BUFFER_SIZE] = {0};
					parakeet_gen_encoded_silence(fill_data, &rh->impl, len);

					while(diff > 1) {
						apr_size_t fill_len = len;
						dzlog_debug("native write, diff(%ld).", diff);
						parakeet_core_file_write(&rh->out_fh, fill_data, &fill_len);
						diff--;
					}
				}
			}

			parakeet_core_file_write(&rh->out_fh, nframe->data, &len);

			rh->last_write_time = now;
			rh->writes++;
		}
			break;
		case PARAKEET_ABC_TYPE_CLOSE:
		{
			parakeet_codec_implementation_t impl = { 0 };
			parakeet_stream_get_codec_impl(stream, &impl);

			if (rh->native) {
			    dzlog_debug("Stop recording file %s\n", rh->in_fh.file);
				dzlog_debug("Stop recording file %s\n", rh->out_fh.file);
				parakeet_core_file_close(&rh->in_fh);
				parakeet_core_file_close(&rh->out_fh);
			} else {
				dzlog_debug("Stop recording file %s\n", rh->file);
				apr_size_t len;
				uint8_t data[PARAKEET_RECOMMENDED_BUFFER_SIZE];
				parakeet_frame_t frame = { 0 };

				if (rh->thread_ready) {
					apr_status_t st;

					rh->thread_ready = 0;
					apr_thread_join(&st, rh->thread);
				}

				if (rh->thread_buffer) {
					parakeet_buffer_destroy(&rh->thread_buffer);
				}

				//frame.data = data;
				//frame.buflen = PARAKEET_RECOMMENDED_BUFFER_SIZE;

				while (parakeet_core_media_bug_read(bug, &frame, TRUE) == PARAKEET_STATUS_OK) {
					len = (apr_size_t) frame.datalen / 2;

					if (len && parakeet_core_file_write(&rh->fh, data, &len) != PARAKEET_STATUS_OK) {
						dzlog_error("Error writing %s\n", rh->file);
						return FALSE;
					}
				}
				parakeet_core_file_close(&rh->fh);
			}
		}

			break;
		case PARAKEET_ABC_TYPE_READ_PING:
		{
			apr_size_t len;
			uint8_t data[PARAKEET_RECOMMENDED_BUFFER_SIZE];
			parakeet_frame_t frame = { 0 };
			apr_status_t status;
			int i = 0;

			//frame.data = data;
			//frame.buflen = PARAKEET_RECOMMENDED_BUFFER_SIZE;

			for (;;) {
				status = parakeet_core_media_bug_read(bug, &frame, i++ == 0 ? FALSE : TRUE);

				if (status != APR_SUCCESS || !frame.datalen) {
					break;
				} else {
					len = (apr_size_t) frame.datalen / 2 / frame.channels;

					if (rh->thread_buffer) {
						apr_thread_mutex_lock(rh->buffer_mutex);
						parakeet_buffer_write(rh->thread_buffer, data, frame.datalen);
						apr_thread_mutex_unlock(rh->buffer_mutex);
					} else if (parakeet_core_file_write(&rh->fh, data, &len) != PARAKEET_STATUS_OK) {
						dzlog_error("Error writing %s\n", rh->file);
			
						return FALSE;
					}

					rh->writes++;
				}
			}
		}
			break;
		case PARAKEET_ABC_TYPE_WRITE:
			/* do nothing */
			break;
		default:
			break;
	}

	return TRUE;
}



parakeet_errcode_t parakeet_stream_create(const char* callid, enum session_direction_t direct, 
                                              apr_port_t caller_port, apr_port_t callee_port, uint8_t pt)
{
	parakeet_errcode_t err = PARAKEET_STATUS_OK;
	apr_status_t  status = APR_SUCCESS;
	parakeet_media_bug_flag_t bug_flags = PMBF_BOTH;  
	parakeet_file_flag_t file_flags = PARAKEET_FILE_FLAG_WRITE;
	//parakeet_stream_flag_t stream_flags;
	parakeet_stream_t * stream;
	parakeet_record_helper_t * rh;
	parakeet_media_bug_t *bug;
	apr_pool_t * pool;
	char * in_path = NULL;
	char * out_path = NULL;
	char * file_path = NULL;
	//apr_threadattr_t * frame_thd_attr = NULL;
	//apr_threadattr_t * record_thd_attr = NULL;
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

	/* codec implementation 赋值 */

    /**
	*
	* 注意，后续session需要解析SDP，单独封装独立rtp帧的信息。
	* 正式使用时，从rtp帧获取信息，此处是暂时的处理
    */
	stream->impl.actual_samples_per_second = 8000;
	stream->impl.microseconds_per_packet  = 20000;                /* ptime * 1000 */
	stream->impl.codec_type = PARAKEET_CODEC_TYPE_AUDIO;
	stream->impl.codec_id   = (uint32_t)pt;
	
	//rtp帧
	//队列初始化
	apr_queue_create(&stream->raw_queue_in, 200, pool);
	apr_queue_create(&stream->raw_queue_out, 200, pool);

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

		err = PARAKEET_STATUS_INUSE;
		goto done;
	}

	rh = apr_pcalloc(pool, sizeof(parakeet_record_helper_t));

    assert(rh);

    rh->pool = pool;

	if(PARAKEET_RECORD_FMT_NATIVE == stream_globals->record_fmt){
		file_flags |= PARAKEET_FILE_NATIVE;
		bug_flags |= PMBF_READ_STREAM;
	    bug_flags |= PMBF_WRITE_STREAM;
        in_path = apr_psprintf(stream->pool, "../var/%s-%u-%u-in.%s", callid, caller_port, callee_port, get_audio_codec_name(pt));
	    parakeet_core_file_open(&rh->in_fh, in_path, 1, 8000, file_flags, pool);
		if(status != APR_SUCCESS){
		    dzlog_error("native audio file open error %s:%s\n", callid, in_path);
			err = PARAKEET_STATUS_GENERR;
		    goto done;
		}
		out_path = apr_psprintf(stream->pool, "../var/%s-%u-%u-out.%s", callid, caller_port, callee_port, get_audio_codec_name(pt));
		parakeet_core_file_open(&rh->out_fh, out_path, 1, 8000, file_flags, pool);
		if(status != APR_SUCCESS){
		    dzlog_error("native audio file open error %s:%s\n", callid, out_path);
			err = PARAKEET_STATUS_GENERR;
		    goto done;
		}
		//保存文件名字
		rh->in_fh.file = in_path;
		rh->out_fh.file = out_path;
		
	}
	else {
		file_path = apr_psprintf(stream->pool, "../var/%s-%u-%u.wav", callid, caller_port, callee_port);
	    file_flags = (PARAKEET_RECORD_FMT_STEREO == stream_globals->record_fmt) ? file_flags|PARAKEET_FILE_NOMUX: file_flags;
	    bug_flags |= PMBF_READ_PING;
        status = parakeet_core_file_open(&rh->out_fh, out_path, 1, 8000, file_flags, pool);
		if(status != APR_SUCCESS){
		    dzlog_error("audio file open error callid: %s filename:%s ", callid, file_path);
			err = PARAKEET_STATUS_GENERR;
			goto done;
		}
		rh->file = file_path; 
		rh->fh.file = file_path;
	}
	apr_thread_rwlock_create(&stream->bug_rwlock, pool);

    //添加bugging
	parakeet_core_media_bug_add(stream, "session_record", NULL, record_callback, rh, 0, bug_flags, &bug);

    // buggging 初始化

    //rtp帧处理线程
    parakeet_set_flag(stream, PSSF_STREAM_OPEN);
	
	//apr_threadattr_create(&frame_thd_attr, pool);
	//线程栈大小系统默认为8M，8192 * 1024byte
	//调优 240* 1024 bytes
	//apr_threadattr_stacksize_set(frame_thd_attr, 240 * 1024);
	//apr_thread_create(&stream->thread, frame_thd_attr, parakeet_stream_process, stream, pool);    


    //录音线程
    //apr_threadattr_create(&record_thd_attr, pool);
	//线程栈大小系统默认为8M，8192 * 1024byte
	//调优 240* 1024 bytes
	//apr_threadattr_stacksize_set(record_thd_attr, 240 * 1024);
	//apr_thread_create(&rh->thread, record_thd_attr, recording_thread, stream->rh, pool);

	stream->rh = rh;

	parakeet_stream_unlock(stream);

done:
	return err;
}

parakeet_stream_t * parakeet_stream_locate(const apr_port_t port)
{
	// 根据local port 查找流且加锁
	parakeet_stream_t * stream = 0;

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

uint32_t parakeet_core_media_bug_test_flag(parakeet_media_bug_t *bug, uint32_t flag)
{
	return parakeet_set_flag(bug, flag);
}

uint32_t parakeet_core_media_bug_set_flag(parakeet_media_bug_t *bug, uint32_t flag)
{
	if ((flag & PMBF_PRUNE)) {
		parakeet_clear_flag(bug, PMBF_LOCK);
	}
	return parakeet_set_flag(bug, flag);
}

static void parakeet_core_media_bug_destroy(parakeet_media_bug_t **bug)
{
	parakeet_media_bug_t *bp = *bug;

	*bug = NULL;
	
	if (bp->raw_read_buffer) {
		parakeet_buffer_destroy(&bp->raw_read_buffer);
	}

	if (bp->raw_write_buffer) {
		parakeet_buffer_destroy(&bp->raw_write_buffer);
	}
}

parakeet_frame_t* parakeet_core_media_bug_get_native_read_frame(parakeet_media_bug_t *bug)
{
    return bug->native_read_frame;
}

parakeet_frame_t* parakeet_core_media_bug_get_native_write_frame(parakeet_media_bug_t *bug)
{
 	return bug->native_write_frame;
}

void parakeet_core_media_bug_flush(parakeet_media_bug_t *bug)
{
	bug->record_pre_buffer_count = 0;

	if (bug->raw_read_buffer) {
		apr_thread_mutex_lock(bug->read_mutex);
		parakeet_buffer_zero(bug->raw_read_buffer);
		apr_thread_mutex_unlock(bug->read_mutex);
	}

	if (bug->raw_write_buffer) {
		apr_thread_mutex_lock(bug->write_mutex);
		parakeet_buffer_zero(bug->raw_write_buffer);
		apr_thread_mutex_unlock(bug->write_mutex);
	}

	bug->record_frame_size = 0;
	bug->record_pre_buffer_count = 0;
}

parakeet_errcode_t parakeet_core_media_bug_read(parakeet_media_bug_t *bug, parakeet_frame_t *frame, parakeet_bool_t fill)
{
	apr_size_t bytes = 0, datalen = 0;
	int16_t *dp, *fp;
	uint32_t x;
	apr_size_t rlen = 0;
	apr_size_t wlen = 0;
	uint32_t blen;
	parakeet_codec_implementation_t read_impl = { 0 };
	int16_t *tp;
	apr_size_t do_read = 0, do_write = 0, has_read = 0, has_write = 0, fill_read = 0, fill_write = 0;

	parakeet_stream_get_codec_impl(bug->stream, &read_impl);

	bytes = read_impl.decoded_bytes_per_packet;

	if (frame->buflen < bytes) {
		dzlog_error("%s frame buffer too small!\n", bug->stream->callid);
		return PARAKEET_STATUS_FAIL;
	}

	if ((!bug->raw_read_buffer && (!bug->raw_write_buffer || !parakeet_test_flag(bug, PMBF_WRITE_STREAM)))) {
		dzlog_error("%s Buffer Error (raw_read_buffer=%p, raw_write_buffer=%p, read=%s, write=%s)\n",
			    bug->stream->callid,
				(void *)bug->raw_read_buffer, (void *)bug->raw_write_buffer,
				parakeet_test_flag(bug, PMBF_READ_STREAM) ? "yes" : "no",
				parakeet_test_flag(bug, PMBF_WRITE_STREAM) ? "yes" : "no");
		return PARAKEET_STATUS_FAIL;
	}

	frame->flags = 0;
	frame->datalen = 0;

	if (parakeet_test_flag(bug, PMBF_READ_STREAM)) {
		has_read = 1;
		apr_thread_mutex_lock(bug->read_mutex);
		do_read = parakeet_buffer_inuse(bug->raw_read_buffer);
		apr_thread_mutex_unlock(bug->read_mutex);
	}

	if (parakeet_test_flag(bug, PMBF_WRITE_STREAM)) {
		has_write = 1;
		apr_thread_mutex_lock(bug->write_mutex);
		do_write = parakeet_buffer_inuse(bug->raw_write_buffer);
		apr_thread_mutex_unlock(bug->write_mutex);
	}


	if (bug->record_frame_size && bug->record_pre_buffer_max && (do_read || do_write) && bug->record_pre_buffer_count < bug->record_pre_buffer_max) {
		bug->record_pre_buffer_count++;
		return PARAKEET_STATUS_FAIL;
	} else {
		uint32_t frame_size;
		parakeet_codec_implementation_t read_impl = { 0 };

		parakeet_stream_get_codec_impl(bug->stream, &read_impl);
		frame_size = read_impl.decoded_bytes_per_packet;
		bug->record_frame_size = frame_size;
	}

	if (bug->record_frame_size && do_write > do_read && do_write > (bug->record_frame_size * 2)) {
		apr_thread_mutex_lock(bug->write_mutex);
		parakeet_buffer_toss(bug->raw_write_buffer, bug->record_frame_size);
		do_write = parakeet_buffer_inuse(bug->raw_write_buffer);
		apr_thread_mutex_unlock(bug->write_mutex);
	}

	if ((has_read && !do_read)) {
		fill_read = 1;
	}

	if ((has_write && !do_write)) {
		fill_write = 1;
	}


	if (bug->record_frame_size) {
		if ((do_read && do_read < bug->record_frame_size) || (do_write && do_write < bug->record_frame_size)) {
			return PARAKEET_STATUS_FAIL;
		}

		if (do_read && do_read > bug->record_frame_size) {
			do_read = bug->record_frame_size;
		}

		if (do_write && do_write > bug->record_frame_size) {
			do_write = bug->record_frame_size;
		}
	}

	if ((fill_read && fill_write) || (fill && (fill_read || fill_write))) {
		return PARAKEET_STATUS_FAIL;
	}

	if (do_read && do_read > PARAKEET_RECOMMENDED_BUFFER_SIZE) {
		do_read = 1280;
	}

	if (do_write && do_write > PARAKEET_RECOMMENDED_BUFFER_SIZE) {
		do_write = 1280;
	}

	if (do_read) {
		apr_thread_mutex_lock(bug->read_mutex);
		frame->datalen = (uint32_t) parakeet_buffer_read(bug->raw_read_buffer, frame->data, do_read);
		if (frame->datalen != do_read) {
			dzlog_error("%s Framing Error Writing!\n", bug->stream->callid);
			parakeet_core_media_bug_flush(bug);
			apr_thread_mutex_unlock(bug->read_mutex);
			return PARAKEET_STATUS_FAIL;
		}
		apr_thread_mutex_unlock(bug->read_mutex);
	} else if (fill_read) {
		frame->datalen = (uint32_t)bytes;
		memset(frame->data, 255, frame->datalen);
	}

	if (do_write) {
		assert(bug->raw_write_buffer);
		apr_thread_mutex_lock(bug->write_mutex);
		datalen = (uint32_t) parakeet_buffer_read(bug->raw_write_buffer, bug->data, do_write);
		if (datalen != do_write) {
			dzlog_error("%s Framing Error Writing!\n", bug->stream->callid);
			parakeet_core_media_bug_flush(bug);
			apr_thread_mutex_unlock(bug->write_mutex);
			return PARAKEET_STATUS_FAIL;
		}
		apr_thread_mutex_unlock(bug->write_mutex);
	} else if (fill_write) {
		datalen = bytes;
		memset(bug->data, 255, datalen);
	}

	tp = bug->tmp;
	dp = (int16_t *) bug->data;
	fp = (int16_t *) frame->data;
	rlen = frame->datalen / 2;
	wlen = datalen / 2;
	blen = (uint32_t)(bytes / 2);

	if (parakeet_test_flag(bug, PMBF_STEREO)) {
		int16_t *left, *right;
		size_t left_len, right_len;
		if (parakeet_test_flag(bug, PMBF_STEREO_SWAP)) {
			left = dp; /* write stream */
			left_len = wlen;
			right = fp; /* read stream */
			right_len = rlen;
		} else {
			left = fp; /* read stream */
			left_len = rlen;
			right = dp; /* write stream */
			right_len = wlen;
		}
		for (x = 0; x < blen; x++) {
			if (x < left_len) {
				*(tp++) = *(left + x);
			} else {
				*(tp++) = 0;
			}
			if (x < right_len) {
				*(tp++) = *(right + x);
			} else {
				*(tp++) = 0;
			}
		}
		memcpy(frame->data, bug->tmp, bytes * 2);
	} else {
		for (x = 0; x < blen; x++) {
			int32_t w = 0, r = 0, z = 0;

			if (x < rlen) {
				r = (int32_t) * (fp + x);
			}

			if (x < wlen) {
				w = (int32_t) * (dp + x);
			}

			z = w + r;

			if (z > PARAKEET_SMAX || z < PARAKEET_SMIN) {
				if (r) z += (r/2);
				if (w) z += (w/2);
			}

			parakeet_normalize_to_16bit(z);

			*(fp + x) = (int16_t) z;
		}
	}

	frame->datalen = (uint32_t)bytes;
	frame->samples = (uint32_t)(bytes / sizeof(int16_t) / read_impl.number_of_channels);
	frame->rate = read_impl.actual_samples_per_second;
	frame->codec = NULL;

	if (parakeet_test_flag(bug, PMBF_STEREO)) {
		frame->datalen *= 2;
		frame->channels = 2;
	} else {
		frame->channels = 1;
	}

	return PARAKEET_STATUS_OK;
}

void *parakeet_core_media_bug_get_user_data(parakeet_media_bug_t *bug)
{
	return bug->user_data;
}

parakeet_stream_t* parakeet_core_media_bug_get_stream(parakeet_media_bug_t *bug)
{
	return bug->stream;
}

parakeet_errcode_t parakeet_core_media_bug_add(parakeet_stream_t *stream, const char *function, const char *target,
                                                       parakeet_media_bug_callback_t callback, void *user_data, time_t stop_time,
                                                       parakeet_media_bug_flag_t flags, parakeet_media_bug_t **new_bug)
{
    parakeet_media_bug_t* bug, *bp;
	apr_size_t bytes;
	int tap_only = 1;
	int punt = 0;

	if(!zstr(function)){
        if((flags & PMBF_ONE_ONLY)){
            apr_thread_rwlock_wrlock(stream->bug_rwlock);
			for(bp = stream->bugs; bp; bp = bp->next){
                if(!zstr(bp->function) && !strcasecmp(function, bp->function)){
                    punt = 1;
					break;
				}
			}
			apr_thread_rwlock_unlock(stream->bug_rwlock);
		}
	}

	if (punt) {
		dzlog_error("Only one bug of this type allowed!\n");
		return PARAKEET_STATUS_GENERR;
	}

	*new_bug = NULL;
	
	if (!(bug = apr_palloc(stream->pool, sizeof(*bug)))) {
		return PARAKEET_STATUS_MEMERR;
	}

	bug->callback = callback;
	bug->user_data = user_data;
	bug->stream = stream;
	bug->flags = flags;
	bug->function = "N/A";
	bug->target = "N/A";

	if (function) {
		bug->function = apr_pstrdup(stream->pool, function);
	}

	if (target) {
		bug->target = apr_pstrdup(stream->pool, target);
	}

	bug->stop_time = stop_time;
	bytes = stream->decoded_bytes_per_packet;

	if (!bug->flags) {
		bug->flags = (PMBF_READ_STREAM | PMBF_WRITE_STREAM);
	}

	if (parakeet_test_flag(bug, PMBF_READ_STREAM) || parakeet_test_flag(bug, PMBF_READ_PING)) {
		parakeet_buffer_create_dynamic(&bug->raw_read_buffer, bytes * 25, bytes * 50, 1024 * 512);
		apr_thread_mutex_create(&bug->read_mutex, APR_THREAD_MUTEX_NESTED, stream->pool);
	    
	}

	if (parakeet_test_flag(bug, PMBF_WRITE_STREAM)) {
		parakeet_buffer_create_dynamic(&bug->raw_write_buffer, bytes * 25, bytes * 50, 1024 * 512);
	    apr_thread_mutex_create(&bug->write_mutex, APR_THREAD_MUTEX_NESTED, stream->pool);
	}

	if ((bug->flags & PMBF_THREAD_LOCK)) {
		bug->thread_id = pthread_self();
	}


	if (bug->callback) {
		parakeet_bool_t result = bug->callback(bug, bug->user_data, PARAKEET_ABC_TYPE_INIT);
		if (result == FALSE) {
			parakeet_core_media_bug_destroy(&bug);
			dzlog_error("Error attaching BUG to %s\n", stream->callid);
			return PARAKEET_STATUS_GENERR;
		}
	}

	bug->ready = 1;

	dzlog_debug("Attaching BUG to %s and remote_port[%u]\n", stream->callid, stream->remote_port);
	apr_thread_rwlock_wrlock(stream->bug_rwlock);
	bug->next = stream->bugs;
	stream->bugs = bug;

	for(bp = stream->bugs; bp; bp = bp->next) {
		if (bp->ready && !parakeet_test_flag(bp, PMBF_TAP_NATIVE_READ) && !parakeet_test_flag(bp, PMBF_TAP_NATIVE_WRITE)) {
			tap_only = 0;
		}
	}

	if (tap_only) {
		parakeet_set_flag(stream, PSF_MEDIA_BUG_TAP_ONLY);
	} else {
		parakeet_clear_flag(stream, PSF_MEDIA_BUG_TAP_ONLY);
	}

	apr_thread_rwlock_unlock(stream->bug_rwlock);
	*new_bug = bug;

    return PARAKEET_STATUS_OK;
}

parakeet_errcode_t parakeet_core_media_bug_remove(parakeet_stream_t *stream, parakeet_media_bug_t **bug)
{
   parakeet_media_bug_t *bp = NULL, *bp2 = NULL, *last = NULL;
   parakeet_errcode_t status = PARAKEET_STATUS_FAIL;
   int tap_only = 0;

   if (parakeet_core_media_bug_test_flag(*bug, PMBF_LOCK)) {
	   return status;
   }

   apr_thread_rwlock_rdlock(stream->bug_rwlock);
   if (stream->bugs) {
	   for (bp = stream->bugs; bp; bp = bp->next) {
		   if ((!bp->thread_id || bp->thread_id == pthread_self()) && bp->ready && bp == *bug) {
			   if (last) {
				   last->next = bp->next;
			   } else {
				   stream->bugs = bp->next;
			   }
			   break;
		   }

		   last = bp;
	   }
   }

   if (stream->bugs) {
	   for(bp2 = stream->bugs; bp2; bp2 = bp2->next) {
		   if (bp2->ready && !parakeet_test_flag(bp2, PMBF_TAP_NATIVE_READ) && !parakeet_test_flag(bp2, PMBF_TAP_NATIVE_WRITE)) {
			   tap_only = 0;
		   }
	   }
   }
   
   if (tap_only) {
	   parakeet_set_flag(stream, PSF_MEDIA_BUG_TAP_ONLY);
   } else {
	   parakeet_clear_flag(stream, PSF_MEDIA_BUG_TAP_ONLY);
   }

   apr_thread_rwlock_unlock(stream->bug_rwlock);

   //if (bp) {
   //   status = parakeet_core_media_bug_close(&bp, TRUE);
   //}
   return status;
}


parakeet_errcode_t parakeet_core_media_bug_close(parakeet_media_bug_t **bug, parakeet_bool_t destroy)
{
	parakeet_media_bug_t *bp = *bug;

	if (bp) {
		if ((bp->thread_id && bp->thread_id != pthread_self()) || parakeet_test_flag(bp, PMBF_LOCK)) {
			dzlog_debug("BUG is thread locked skipping.\n");
			return PARAKEET_STATUS_FAIL;
		}

		if (bp->callback) {
			bp->callback(bp, bp->user_data, PARAKEET_ABC_TYPE_CLOSE);
		}

		bp->ready = 0;

		dzlog_debug("Removing BUG from %s\n", bp->stream->callid);

		if (destroy) {
			parakeet_core_media_bug_destroy(bug);
		}

		return PARAKEET_STATUS_OK;
	}

	return PARAKEET_STATUS_FAIL;
}

uint32_t parakeet_core_media_bug_prune(parakeet_stream_t *stream)
{
	parakeet_media_bug_t *bp = NULL, *last = NULL;
	int ttl = 0;

  top:

	apr_thread_rwlock_wrlock(stream->bug_rwlock);
	if (stream->bugs) {
		for (bp = stream->bugs; bp; bp = bp->next) {
			if (parakeet_test_flag(bp, PMBF_PRUNE)) {
				if (last) {
					last->next = bp->next;
				} else {
					stream->bugs = bp->next;
				}
				break;
			}

			last = bp;
		}
	}

	//if (!stream->bugs && switch_core_codec_ready(&session->bug_codec)) {
	//	parakeet_core_codec_destroy(&session->bug_codec);
	//}

	apr_thread_rwlock_unlock(stream->bug_rwlock);

	if (bp) {
		parakeet_clear_flag(bp, PMBF_LOCK);
		bp->thread_id = 0;
		parakeet_core_media_bug_close(&bp, TRUE);
		ttl++;
		goto top;
	}

	return ttl;
}

void parakeet_gen_encoded_silence(unsigned char *data, const parakeet_codec_implementation_t *read_impl, apr_size_t len)
{
	unsigned char g729_filler[] = {
		114, 170, 250, 103, 54, 211, 203, 194, 94, 64,
		229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
		114, 170, 250, 103, 54, 211, 203, 194, 94, 64,
		229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
		114, 170, 250, 103, 54, 211, 203, 194, 94, 64,
		229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
		114, 170, 250, 103, 54, 211, 203, 194, 94, 64,
		229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
		114, 170, 250, 103, 54, 211, 203, 194, 94, 64,
		229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
		114, 170, 250, 103, 54, 211, 203, 194, 94, 64,
		229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
		114, 170, 250, 103, 54, 211, 203, 194, 94, 64,
		229, 127, 79, 96, 207, 82, 216, 110, 245, 81
	};

	if (read_impl->ianacode == 18) {
		memcpy(data, g729_filler, len);
	} else {
		memset(data, 255, len);
	}
}

void parakeet_mux_channels(int16_t *data, apr_size_t samples, uint32_t orig_channels, uint32_t channels)
{
	apr_size_t i = 0;
	uint32_t j = 0;

	assert(channels < 11);

	if (orig_channels > channels) {
		for (i = 0; i < samples; i++) {
			int32_t z = 0;
			for (j = 0; j < orig_channels; j++) {
				z += data[i * orig_channels + j];
				parakeet_normalize_to_16bit(z);
				data[i] = (int16_t) z;
			}
		}
	} else if (orig_channels < channels) {

		/* interesting problem... take a give buffer and double up every sample in the buffer without using any other buffer.....
		   This way beats the other i think bacause there is no malloc but I do have to copy the data twice */
#if 1
		uint32_t k = 0, len = samples * orig_channels;

		for (i = 0; i < len; i++) {
			data[i+len] = data[i];
		}

		for (i = 0; i < samples; i++) {
			for (j = 0; j < channels; j++) {
				data[k++] = data[i + samples];
			}
		}

#else
		uint32_t k = 0, len = samples * 2 * orig_channels;
		int16_t *orig = NULL;

		switch_zmalloc(orig, len);
		memcpy(orig, data, len);

		for (i = 0; i < samples; i++) {
			for (j = 0; j < channels; j++) {
				data[k++] = orig[i];
			}
		}

		free(orig);
#endif

	}
}



#if 0

//static void *APR_THREAD_FUNC parakeet_stream_process(apr_thread_t *thread, void *obj)
static parakeet_errcode_t parakeet_stream_process(parakeet_stream_t* stream)
{
	unsigned char null_data[PARAKEET_RECOMMENDED_BUFFER_SIZE] = {0};
	parakeet_errcode_t  errcode = PARAKEET_STATUS_OK;
    apr_queue_t* in_queue = NULL;
    apr_queue_t* out_queue = NULL;
	uint8_t need_fill_out;
	uint8_t need_fill_in;
	rtp_msg_t* rtp_in;
    rtp_msg_t* rtp_out;
	
	assert(stream);

	in_queue = stream->raw_queue_in;
	out_queue = stream->raw_queue_out;

    if(parakeet_test_flag(stream, PSSF_STREAM_OPEN))
	{
	    //双向的队列均为空队列，不处理
		if(!apr_queue_size(in_queue) && !apr_queue_size(out_queue))
		{
		   //打包间隔决定了循环等待时间
	       //apr_sleep(20);
		   //continue;
		   return errcode;
		}
		
        //一个队列非空。一个队列为空。FreeSWITCH执行sleep操作时，rtp数据会停发，此处可用空数据填充
		if(apr_queue_size(in_queue) && !apr_queue_size(out_queue))
		{
		    apr_queue_pop(in_queue, &rtp_in);
			rtp_out = null_data;
		}else if(!apr_queue_size(in_queue) && apr_queue_size(out_queue))
		{
		    rtp_in = null_data;
			apr_queue_pop(in_queue, &rtp_out);
		}
		
       
        if (stream->bugs){
			parakeet_media_bug_t *bp;
			parakeet_bool_t ok = TRUE;
			int prune = 0;

			apr_thread_rwlock_rdlock(stream->bug_rwlock);

			for (bp = stream->bugs; bp; bp = bp->next) {
				ok = TRUE;

				if (parakeet_test_flag(bp, PMBF_PRUNE)) {
					prune++;
					continue;
				}

				if (bp->ready) {
					 //原始帧 read
					if (parakeet_test_flag(bp, PMBF_TAP_NATIVE_READ)) {
						if (bp->callback) {
							bp->native_read_frame = rtp_in;
							ok = bp->callback(bp, bp->user_data, PARAKEET_ABC_TYPE_TAP_NATIVE_READ);
							bp->native_read_frame = NULL;
						}
					}
					//原始帧 write
					if (parakeet_test_flag(bp, PMBF_TAP_NATIVE_WRITE)) {
						if (bp->callback) {
							bp->native_write_frame = rtp_out;
							ok = bp->callback(bp, bp->user_data, PARAKEET_ABC_TYPE_TAP_NATIVE_WRITE);
							bp->native_write_frame = NULL;
						}
					}
					/* 需要解码后的数据 */
				    /* 单声道 */
				    /* 立体声 */
					if(parakeet_test_flag(bp, PMBF_READ_PING)){
						if (bp->callback) {
							bp->native_read_frame = rtp_in;
							bp->native_write_frame = rtp_out;
							ok = bp->callback(bp, bp->user_data, PARAKEET_ABC_TYPE_READ_PING);
							bp->native_read_frame = NULL;
							bp->native_write_frame = NULL;
						}
					}

				}



				//if ((bp->stop_time && bp->stop_time <= apr_time_now(NULL)) || ok == FALSE) {
				//	parakeet_set_flag(bp, PMBF_PRUNE);
				//	prune++;
				//}
				
		
				
			}
			apr_thread_rwlock_unlock(stream->bug_rwlock);

			//if (prune) {
			//	parakeet_core_media_bug_prune(stream);
			//}
		}



		
	}
    return NULL;
}
#endif


