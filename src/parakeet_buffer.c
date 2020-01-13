#include "parakeet_config.h"
#include "parakeet_buffer.h"


static uint32_t buffer_id = 0;

typedef enum {
	PARAKEET_BUFFER_FLAG_DYNAMIC = (1 << 0),
	PARAKEET_BUFFER_FLAG_PARTITION = (1 << 1)
} parakeet_buffer_flag_t;


struct parakeet_buffer_s {
	apr_size_t *data;
	apr_size_t *head;
	apr_size_t used;
	apr_size_t actually_used;
	apr_size_t datalen;
	apr_size_t max_len;
	apr_size_t blocksize;
	apr_thread_mutex_t *mutex;
	uint32_t flags;
	uint32_t id;
	int32_t loops;
};



parakeet_errcode_t parakeet_buffer_create(apr_pool_t *pool, parakeet_buffer_t **buffer, apr_size_t max_len)
{
	parakeet_buffer_t *new_buffer;

	if ((new_buffer = apr_pcalloc(pool, sizeof(parakeet_buffer_t))) != 0 && (new_buffer->data = apr_pcalloc(pool, max_len)) != 0) {
		new_buffer->datalen = max_len;
		new_buffer->id = buffer_id++;
		new_buffer->head = new_buffer->data;
		*buffer = new_buffer;
		return PARAKEET_OK;
	}
	return PARAKEET_MEMERR;
}

parakeet_errcode_t parakeet_buffer_create_dynamic(parakeet_buffer_t **buffer, apr_size_t blocksize, apr_size_t start_len, apr_size_t max_len)
{
	parakeet_buffer_t *new_buffer;

	if ((new_buffer = malloc(sizeof(*new_buffer)))) {
		memset(new_buffer, 0, sizeof(*new_buffer));

		if (start_len) {
			if (!(new_buffer->data = malloc(start_len))) {
				free(new_buffer);
				*buffer = NULL;
				return PARAKEET_MEMERR;
			}
			memset(new_buffer->data, 0, start_len);
		}

		new_buffer->max_len = max_len;
		new_buffer->datalen = start_len;
		new_buffer->id = buffer_id++;
		new_buffer->blocksize = blocksize;
		new_buffer->head = new_buffer->data;
		parakeet_set_flag(new_buffer, PARAKEET_BUFFER_FLAG_DYNAMIC);

		*buffer = new_buffer;
		return PARAKEET_OK;
	}
	*buffer = NULL;
	return PARAKEET_MEMERR;
}


void parakeet_buffer_add_mutex(parakeet_buffer_t *buffer, apr_thread_mutex_t *mutex)
{
	buffer->mutex = mutex;
}

void parakeet_buffer_lock(parakeet_buffer_t *buffer)
{
	if (buffer->mutex) {
		apr_thread_mutex_lock(buffer->mutex);
	}
}

parakeet_errcode_t parakeet_buffer_trylock(parakeet_buffer_t *buffer)
{
	if (buffer->mutex) {
		return apr_thread_mutex_lock(buffer->mutex);
	}
	return PARAKEET_FAIL;
}

void parakeet_buffer_unlock(parakeet_buffer_t *buffer)
{
	if (buffer->mutex) {
		apr_thread_mutex_unlock(buffer->mutex);
	}
}

apr_size_t parakeet_buffer_len(parakeet_buffer_t *buffer)
{
	return buffer->datalen;
}

apr_size_t parakeet_buffer_freespace(parakeet_buffer_t *buffer)
{
	if (parakeet_test_flag(buffer, SWITCH_BUFFER_FLAG_DYNAMIC)) {
		if (buffer->max_len) {
			return (apr_size_t) (buffer->max_len - buffer->used);
		}
		return 1000000;
	}

	return (apr_size_t) (buffer->datalen - buffer->used);
}

apr_size_t parakeet_buffer_inuse(parakeet_buffer_t *buffer)
{
	return buffer->used;
}

void parakeet_buffer_destroy(parakeet_buffer_t * buffer)
{
   if (buffer && *buffer) {
	   if ((parakeet_test_flag((*buffer), PARAKEET_BUFFER_FLAG_DYNAMIC))) {
		   parakeet_safe_free((*buffer)->data);
		   free(*buffer);
	   }
	   *buffer = NULL;
   }
}

apr_size_t parakeet_buffer_write(parakeet_buffer_t *buffer, const void *data, apr_size_t datalen)
{
	apr_size_t freespace, actual_freespace;

	if (parakeet_test_flag(buffer, PARAKEET_BUFFER_FLAG_PARTITION)) {
		return 0;
	}

	assert(buffer->data != NULL);

	if (!datalen) {
		return buffer->used;
	}

	actual_freespace = buffer->datalen - buffer->actually_used;

	if (actual_freespace < datalen) {
		memmove(buffer->data, buffer->head, buffer->used);
		buffer->head = buffer->data;
		buffer->actually_used = buffer->used;
	}

	freespace = buffer->datalen - buffer->used;

	if (parakeet_test_flag(buffer, PARAKEET_BUFFER_FLAG_DYNAMIC)) {
		if (freespace < datalen && (!buffer->max_len || (buffer->used + datalen <= buffer->max_len))) {
			apr_size_t new_size, new_block_size;
			void *tmp;

			new_size = buffer->datalen + datalen;
			new_block_size = buffer->datalen + buffer->blocksize;

			if (new_block_size > new_size) {
				new_size = new_block_size;
			}
			buffer->head = buffer->data;
			if (!(tmp = realloc(buffer->data, new_size))) {
				return 0;
			}
			buffer->data = tmp;
			buffer->head = buffer->data;
			buffer->datalen = new_size;
		}
	}

	freespace = buffer->datalen - buffer->used;

	if (freespace < datalen) {
		return 0;
	}

	memcpy(buffer->head + buffer->used, data, datalen);
	buffer->used += datalen;
	buffer->actually_used += datalen;
	return buffer->used;
}



apr_size_t parakeet_buffer_read(parakeet_buffer_t *buffer, void *data, apr_size_t datalen)
{
	apr_size_t reading = 0;

	if (buffer->used < 1) {
		buffer->used = 0;
		return 0;
	} else if (buffer->used >= datalen) {
		reading = datalen;
	} else {
		reading = buffer->used;
	}

	memcpy(data, buffer->head, reading);
	buffer->used -= reading;
	buffer->head += reading;

	return reading;
}

void parakeet_buffer_zero(parakeet_buffer_t *buffer)
{
	assert(buffer->data != NULL);

	buffer->used = 0;
	buffer->actually_used = 0;
	buffer->head = buffer->data;
}


