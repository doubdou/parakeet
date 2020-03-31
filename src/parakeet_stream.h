#ifndef PARAKEET_STREAM_H
#define PARAKEET_STREAM_H

#include "parakeet_config.h"
#include "parakeet_utils.h"
#include "parakeet_buffer.h"
#include "parakeet_core_file.h"
#include "parakeet_session.h"
#include "parakeet_codec.h"

typedef struct parakeet_frame_s parakeet_frame_t;

/*! \brief An abstraction of a data frame */
struct parakeet_frame_s {
	/*! a pointer to the codec information */
	parakeet_codec_t *codec;
	/*! the originating source of the frame */
	const char *source;
	/*! the raw packet */
	void *packet;
	/*! the size of the raw packet when applicable */
	uint32_t packetlen;
	/*! the extra frame data */
	void *extra_data;
	/*! the size of the buffer that is in use */
	uint32_t datalen;
	/*! the entire size of the buffer */
	uint32_t buflen;
	/*! the number of audio samples present (audio only) */
	uint32_t samples;
	/*! the rate of the frame */
	uint32_t rate;
	/*! the number of channels in the frame */
	uint32_t channels;
	/*! the payload of the frame */
	parakeet_payload_t payload;
	/*! the timestamp of the frame */
	uint32_t timestamp;
	uint16_t seq;
	uint32_t ssrc;
	int m; 
	/*! frame flags */
	parakeet_frame_flag_t flags;
	void *user_data;
	/*! the frame data */
	char data[0];
};

typedef struct parakeet_media_bug_s parakeet_media_bug_t;

typedef struct parakeet_stream_t parakeet_stream_t;

typedef parakeet_bool_t (*parakeet_media_bug_callback_t) (parakeet_media_bug_t *, void *, parakeet_abc_type_t);

struct parakeet_media_bug_s {
	parakeet_buffer_t* raw_read_buffer;
	parakeet_buffer_t* raw_write_buffer;
	parakeet_frame_t* native_read_frame;
	parakeet_frame_t* native_write_frame;
	parakeet_media_bug_callback_t callback;
	apr_thread_mutex_t *read_mutex;
	apr_thread_mutex_t *write_mutex;
	char * callid;                      ///< 媒体通道所属会话的callid
	parakeet_stream_t* stream;
	void *user_data;
	uint32_t flags;
	uint8_t ready;
	uint8_t data[PARAKEET_RECOMMENDED_BUFFER_SIZE];
	int16_t tmp[PARAKEET_RECOMMENDED_BUFFER_SIZE];
	time_t stop_time;
	pthread_t thread_id;
	char *function;
	char *target;
	//parakeet_codec_implementation_t impl;
	uint32_t record_frame_size;
	uint32_t record_pre_buffer_count;
	uint32_t record_pre_buffer_max;

	struct parakeet_media_bug_s *next;
};


typedef struct parakeet_record_helper_t parakeet_record_helper_t;

struct parakeet_record_helper_t{
	apr_pool_t * pool;   ///< 内存池
	char *file;
	parakeet_codec_implementation_t impl;
	
	apr_thread_mutex_t *buffer_mutex;

	uint32_t writes;

	parakeet_file_handle_t fh;
	parakeet_file_handle_t in_fh;
	parakeet_file_handle_t out_fh;
	int native;

	parakeet_buffer_t *thread_buffer;
	apr_thread_t *thread;
    int thread_ready;

    int rready;
    int wready;
	
	apr_time_t last_read_time;
	apr_time_t last_write_time;
	
};

typedef enum {
	PSF_NONE = 0,
	PSF_DESTROYED = (1 << 0),
	PSF_WARN_TRANSCODE = (1 << 1),
	PSF_HANGUP = (1 << 2),
	PSF_THREAD_STARTED = (1 << 3),
	PSF_THREAD_RUNNING = (1 << 4),
	PSF_READ_TRANSCODE = (1 << 5),
	PSF_WRITE_TRANSCODE = (1 << 6),
	PSF_READ_CODEC_RESET = (1 << 7),
	PSF_WRITE_CODEC_RESET = (1 << 8),
	PSF_DESTROYABLE = (1 << 9),
	PSF_MEDIA_BUG_TAP_ONLY = (1 << 10)
} parakeet_stream_flag_t;

struct parakeet_stream_t{
	apr_pool_t * pool;				    ///< 保存信息的内存池, 每条媒体使用独立的内存池.
    char * callid;                      ///< 媒体通道所属会话的callid
    apr_thread_mutex_t * mutex;		    ///< 互斥锁
    uint8_t pt;                         ///< 有效负载类型
    rtp_header_t* last_rtp_hdr;         ///< 前回rtp头域
    apr_port_t remote_port;             ///< 远端媒体端口

	apr_thread_rwlock_t *bug_rwlock;
	parakeet_media_bug_t *bugs;
	apr_thread_t *thread;

	parakeet_codec_implementation_t impl;

	apr_uint32_t flags;
    apr_queue_t* raw_queue_in;          ///< 队列，存原始音频帧
    apr_queue_t* raw_queue_out;         ///< 队列，原始数据缓存

	uint32_t decoded_bytes_per_packet;  ///< 一个rtp包中将被解码的负载字节数
	uint32_t encoded_bytes_per_packet;  ///< 一个rtp包中经过编码的负载字节数     
    parakeet_record_helper_t* rh;       
};

typedef struct parakeet_stream_manager_t parakeet_stream_manager_t;

struct parakeet_stream_manager_t
{
	apr_pool_t * pool;				       ///< 内存池.
    parakeet_stream_t * streams[65536];    ///< 保存所有媒体数据流信息. 数据面操作最多的数据.以本地端口为索引
    apr_thread_rwlock_t * map_lock;	       ///< 对map加锁
    parakeet_record_fmt_t record_fmt;    ///< 录音格式
    //uint32_t sum_of_streams;              ///< 活跃的媒体流数量
};

parakeet_errcode_t parakeet_stream_factory_init(apr_pool_t * pool);

parakeet_errcode_t parakeet_stream_create(const char* callid, enum session_direction_t direct, 
                                                apr_port_t caller_port, apr_port_t callee_port, uint8_t pt);

parakeet_stream_t * parakeet_stream_locate(const apr_port_t port);

void parakeet_stream_unlock(parakeet_stream_t * stream);

uint32_t parakeet_core_media_bug_test_flag(parakeet_media_bug_t *bug, uint32_t flag);

uint32_t parakeet_core_media_bug_set_flag(parakeet_media_bug_t *bug, uint32_t flag);

parakeet_frame_t* parakeet_core_media_bug_get_native_read_frame(parakeet_media_bug_t *bug);

parakeet_frame_t* parakeet_core_media_bug_get_native_write_frame(parakeet_media_bug_t *bug);

void parakeet_core_media_bug_flush(parakeet_media_bug_t *bug);

parakeet_errcode_t parakeet_core_media_bug_read(parakeet_media_bug_t *bug, parakeet_frame_t *frame, parakeet_bool_t fill);

void *parakeet_core_media_bug_get_user_data(parakeet_media_bug_t *bug);

parakeet_stream_t* parakeet_core_media_bug_get_stream(parakeet_media_bug_t *bug);

parakeet_errcode_t parakeet_core_media_bug_add(parakeet_stream_t *stream, const char *function, const char *target,
                                                       parakeet_media_bug_callback_t callback, void *user_data, time_t stop_time,
                                                       parakeet_media_bug_flag_t flags, parakeet_media_bug_t **new_bug);

parakeet_errcode_t parakeet_core_media_bug_remove(parakeet_stream_t *stream, parakeet_media_bug_t **bug);

parakeet_errcode_t parakeet_core_media_bug_close(parakeet_media_bug_t **bug, parakeet_bool_t destroy);

uint32_t parakeet_core_media_bug_prune(parakeet_stream_t *stream);

void parakeet_gen_encoded_silence(unsigned char *data, const parakeet_codec_implementation_t *read_impl, apr_size_t len);

void parakeet_mux_channels(int16_t *data, apr_size_t samples, uint32_t orig_channels, uint32_t channels);

#endif
