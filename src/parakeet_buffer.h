#ifndef PARAKEET_BUFFER_H
#define PARAKEET_BUFFER_H

#include "parakeet_config.h"

typedef enum {
	PARAKEET_BUFFER_FLAG_DYNAMIC = (1 << 0),
	PARAKEET_BUFFER_FLAG_PARTITION = (1 << 1)
} parakeet_buffer_flag_t;

typedef struct parakeet_buffer_s parakeet_buffer_t;

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

parakeet_errcode_t parakeet_buffer_create(apr_pool_t *pool, parakeet_buffer_t **buffer, apr_size_t max_len);

parakeet_errcode_t parakeet_buffer_create_dynamic(parakeet_buffer_t **buffer, apr_size_t blocksize, apr_size_t start_len, apr_size_t max_len);


void parakeet_buffer_add_mutex(parakeet_buffer_t *buffer, apr_thread_mutex_t *mutex);

void parakeet_buffer_lock(parakeet_buffer_t *buffer);

parakeet_errcode_t parakeet_buffer_trylock(parakeet_buffer_t *buffer);

void parakeet_buffer_unlock(parakeet_buffer_t *buffer);

apr_size_t parakeet_buffer_len(parakeet_buffer_t *buffer);

apr_size_t parakeet_buffer_freespace(parakeet_buffer_t *buffer);

apr_size_t parakeet_buffer_inuse(parakeet_buffer_t *buffer);

apr_size_t parakeet_buffer_toss(parakeet_buffer_t *buffer, apr_size_t datalen);

void parakeet_buffer_destroy(parakeet_buffer_t** buffer);

apr_size_t parakeet_buffer_write(parakeet_buffer_t *buffer, const void *data, apr_size_t datalen);

apr_size_t parakeet_buffer_read(parakeet_buffer_t *buffer, void *data, apr_size_t datalen);

void parakeet_buffer_zero(parakeet_buffer_t *buffer);



#endif

