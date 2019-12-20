#pragma once

#include "sip_utils.h"

struct sip_session_expires_t
{
	apr_pool_t * pool;
	apr_uint32_t  expires;
	const char * refresher;
};

struct sip_session_expires_t * sip_session_expires_make(apr_pool_t * pool);
struct sip_session_expires_t * sip_session_expires_parse(apr_pool_t * pool, const char * buff);
struct sip_session_expires_t * sip_session_expires_clone(apr_pool_t * pool, const struct sip_session_expires_t * src);
int  sip_session_expires_to_string(const struct sip_session_expires_t * se, char * buff, int len);

#define sip_session_expires_set_expires(se, e) (se)->expires=(apr_uint32_t)e
#define sip_session_expires_set_refresher(se,r) (se)->refresher=apr_pstrdup((se)->pool,r)
#define sip_session_expires_get_expires(se) ((se)->expires)
#define sip_session_expires_get_refresher(se) (se)->refresher
