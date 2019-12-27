#ifndef PARAKEET_BUFFER_H
#define PARAKEET_BUFFER_H

#include "parakeet_config.h"

typedef struct parakeet_buffer_t parakeet_buffer_t;

struct parakeet_buffer_t {
	apr_byte_t *data;
	apr_byte_t *head;
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

parakeet_buffer_t * parakeet_buffer_create(apr_pool_t * pool);

parakeet_errcode_t parakeet_buffer_destroy(parakeet_buffer_t * buffer);

apr_size_t parakeet_buffer_write(parakeet_buffer_t *buffer, const void *data, apr_size_t datalen);


#endif

