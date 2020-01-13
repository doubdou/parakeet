#ifndef PARAKEET_BUFFER_H
#define PARAKEET_BUFFER_H

#include "parakeet_config.h"

typedef struct parakeet_buffer_s parakeet_buffer_t;

parakeet_errcode_t parakeet_buffer_create(apr_pool_t *pool, parakeet_buffer_t **buffer, apr_size_t max_len);

parakeet_errcode_t parakeet_buffer_create_dynamic(parakeet_buffer_t **buffer, apr_size_t blocksize, apr_size_t start_len, apr_size_t max_len);


void parakeet_buffer_add_mutex(parakeet_buffer_t *buffer, apr_thread_mutex_t *mutex);

void parakeet_buffer_lock(parakeet_buffer_t *buffer);

parakeet_errcode_t parakeet_buffer_trylock(parakeet_buffer_t *buffer);

void parakeet_buffer_unlock(parakeet_buffer_t *buffer);

apr_size_t parakeet_buffer_len(parakeet_buffer_t *buffer);

apr_size_t parakeet_buffer_freespace(parakeet_buffer_t *buffer);

apr_size_t parakeet_buffer_inuse(parakeet_buffer_t *buffer);

parakeet_errcode_t parakeet_buffer_destroy(parakeet_buffer_t * buffer);

apr_size_t parakeet_buffer_write(parakeet_buffer_t *buffer, const void *data, apr_size_t datalen);

apr_size_t parakeet_buffer_read(parakeet_buffer_t *buffer, void *data, apr_size_t datalen);

void parakeet_buffer_zero(parakeet_buffer_t *buffer);



#endif

