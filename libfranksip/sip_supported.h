#pragma once

#include "sip_utils.h"

struct sip_supported_t
{
	apr_pool_t * pool;
	apr_hash_t * events;
};


struct sip_supported_t * sip_supported_make(apr_pool_t * pool);
struct sip_supported_t * sip_supported_parse(apr_pool_t * pool, const char * buff);
struct sip_supported_t * sip_supported_clone(apr_pool_t * pool, const struct sip_supported_t * src);
int sip_supported_to_string(const struct sip_supported_t * sup, char * buff, int len);

int  sip_supported_exists(const struct sip_supported_t * sup, const char * evt);
void sip_supported_insert(const struct sip_supported_t * sup, const char * evt);
void sup_supported_remove(const struct sip_supported_t * sup, const char * evt);


