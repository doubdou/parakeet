#include "parakeet_config.h"
#include "parakeet_buffer.h"

parakeet_buffer_t * parakeet_buffer_create(apr_pool_t * pool)
{
	parakeet_buffer_t * buffer;

	buffer = apr_pcalloc(pool, sizeof(parakeet_buffer_t));

    return buffer;
}

parakeet_errcode_t parakeet_buffer_destroy(parakeet_buffer_t * buffer)
{
   parakeet_errcode_t err = PARAKEET_OK;

   return err;
}

apr_size_t parakeet_buffer_write(parakeet_buffer_t *buffer, const void *data, apr_size_t datalen)
{
	apr_size_t freespace, actual_freespace;

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

	if (freespace < datalen) {
		return 0;
	}

	memcpy(buffer->head + buffer->used, data, datalen);
	buffer->used += datalen;
	buffer->actually_used += datalen;
	return buffer->used;
}


