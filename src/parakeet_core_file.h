#ifndef PARAKEET_CORE_FILE_H
#define PARAKEET_CORE_FILE_H

#include "parakeet_buffer.h"
#include "parakeet_utils.h"
#include "parakeet_config.h"

typedef struct parakeet_file_handle parakeet_file_handle_t;

/*! an abstract representation of a file handle (some parameters based on compat with libsndfile) */
struct parakeet_file_handle {
	/*! flags to control behaviour */
	uint32_t flags;       //parakeet_file_flag_enum_t
	/*! a file descriptor if neceessary */
	apr_file_t *fd;
	/*! samples position of the handle */
	unsigned int samples;
	/*! the current samplerate */
	uint32_t samplerate;
	/*! the current native samplerate */
	uint32_t native_rate;
	/*! the number of channels */
	uint32_t channels;
	uint32_t real_channels;
	/*! integer representation of the format */
	unsigned int format;
	/*! integer representation of the sections */
	unsigned int sections;
	/*! is the file seekable */
	int seekable;
	/*! the sample count of the file */
	apr_size_t sample_count;
	/*! the speed of the file playback */
	int speed;
	/*! the handle's memory pool */
	apr_pool_t *memory_pool;
	/*! pre-buffer x bytes for streams */
	uint32_t prebuf;
	/*! private data for the format module to store handle specific info */
	uint32_t interval;
	void *private_info;
	char *handler;
	int64_t pos;
	parakeet_buffer_t *audio_buffer;
	parakeet_buffer_t *sp_audio_buffer;
	uint32_t thresh;
	uint32_t silence_hits;
	uint32_t offset_pos;
	apr_size_t samples_in;
	apr_size_t samples_out;
	int32_t vol;
	parakeet_buffer_t *buffer;
	apr_byte_t *dbuf;
	apr_size_t dbuflen;
	parakeet_buffer_t *pre_buffer;
	unsigned char *pre_buffer_data;
	apr_size_t pre_buffer_datalen;
	const char *file;
	const char *func;
	int line;
	char *file_path;
	char *spool_path;
	const char *prefix;
	int max_samples;
	
	uint32_t cur_channels;
	uint32_t cur_samplerate;
	char *stream_name;
	apr_thread_mutex_t* flag_mutex;
	void *muxbuf;
	apr_size_t muxlen;
};

long filesize(FILE *stream);

parakeet_errcode_t parakeet_core_file_open( parakeet_file_handle_t *fh,const char *file_path,
												 uint32_t channels, uint32_t rate, unsigned int flags, apr_pool_t *pool);

parakeet_errcode_t parakeet_core_file_write(parakeet_file_handle_t *fh, void *data, apr_size_t *len);

parakeet_errcode_t parakeet_core_file_close(parakeet_file_handle_t* fh);

#endif