#include "parakeet_core_file.h"
#include "parakeet_stream.h"
#include "parakeet_config.h"

long filesize(FILE *stream)
{
    long curpos, length;
	
    curpos = ftell(stream);
    fseek(stream, 0L, SEEK_END);

    length = ftell(stream);
    fseek(stream, curpos, SEEK_SET);
    return length;
}

parakeet_errcode_t parakeet_core_file_open(parakeet_file_handle_t *fh, const char *file_path, 
                                                 uint32_t channels, uint32_t rate, unsigned int flags, apr_pool_t *pool)
{
    apr_status_t status = APR_SUCCESS;

	if (parakeet_test_flag(fh, PARAKEET_FILE_OPEN)) {
		dzlog_error("Handle already open\n");
		return PARAKEET_STATUS_FAIL;
	}

	apr_thread_mutex_create(&fh->flag_mutex, APR_THREAD_MUTEX_NESTED, pool);

	fh->samples_in = 0;
	fh->samplerate = 0;
	fh->native_rate = 0;
	fh->channels = 0;
	fh->real_channels = 0;


	if (!fh->samplerate) {
		if (!(fh->samplerate = rate)) {
			fh->samplerate = 8000;
		}
	}

	if (zstr(file_path)) {
		dzlog_error("Invalid Filename\n");
		return PARAKEET_STATUS_FAIL;
	}


    fh->flags = flags;

	if(pool){
		fh->memory_pool = pool;
	}else {
		dzlog_error("pool is null!\n");
	}
	
	status = apr_file_open(&fh->fd, file_path, APR_FOPEN_WRITE|APR_FOPEN_CREATE, 0777, pool);
	if(status != APR_SUCCESS){
		dzlog_error("%s file open error!", file_path);
		return PARAKEET_STATUS_GENERR;
	}

	parakeet_set_flag_locked(fh, PARAKEET_FILE_OPEN);

	return PARAKEET_STATUS_OK;
}

parakeet_errcode_t parakeet_core_file_close(parakeet_file_handle_t* fh)
{
	parakeet_errcode_t status;

	assert(fh != NULL);

	if (!parakeet_test_flag(fh, PARAKEET_FILE_OPEN)) {
		dzlog_error("close file fail, file is closed.");
	 return PARAKEET_STATUS_FAIL;
	}



	parakeet_clear_flag_locked(fh, PARAKEET_FILE_OPEN);

	fh->samples_in = 0;
	fh->max_samples = 0;

	if (fh->buffer) {
	    parakeet_buffer_destroy(&fh->buffer);
	}

	fh->memory_pool = NULL;

	parakeet_safe_free(fh->dbuf);
	parakeet_safe_free(fh->muxbuf);

	return status;
}


parakeet_errcode_t parakeet_core_file_write(parakeet_file_handle_t *fh, void *data, apr_size_t *len)
{
	apr_size_t orig_len = *len;
    apr_status_t status = APR_SUCCESS;
	
	assert(fh != NULL);

	if (!parakeet_test_flag(fh, PARAKEET_FILE_OPEN)) {
		return PARAKEET_STATUS_FAIL;
	}
	
	if (!parakeet_test_flag(fh, PARAKEET_FILE_NOMUX) && !parakeet_test_flag(fh, PARAKEET_FILE_NATIVE)) {
		int need = *len * 2 * fh->real_channels;

		if (need > fh->muxlen) {
			fh->muxbuf = realloc(fh->muxbuf, need);
			assert(fh->muxbuf);
			fh->muxlen = need;
			memcpy(fh->muxbuf, data, fh->muxlen);
			data = fh->muxbuf;

		}
        dzlog_debug("core file write ...mux...");
		parakeet_mux_channels((int16_t *) data, *len, fh->real_channels, fh->channels);
	}
	
	if ((status = apr_file_write(fh->fd, data, len)) == APR_SUCCESS) {
		fh->sample_count += orig_len;
	}
	return status;	
}



