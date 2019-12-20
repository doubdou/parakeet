#include "sip_session_expires.h"



struct sip_session_expires_t * sip_session_expires_make(apr_pool_t * pool)
{
	struct sip_session_expires_t * se;
	se = apr_pcalloc(pool, sizeof(struct sip_session_expires_t));
	se->pool = pool;
	return se;
}

struct sip_session_expires_t * sip_session_expires_parse(apr_pool_t * pool, const char * buff)
{
	struct sip_session_expires_t * se = 0;
	const char * str = strchr(buff, ';');
	if (str)
	{
		str++;
	}

	se = sip_session_expires_make(pool);
	se->expires = (apr_uint32_t)apr_atoi64(buff);
	
	if (str)
	{
		if (!strncmp(str, "refresher=", 10))
		{
			str += 10;
			se->refresher = apr_pstrdup(pool, str);
		}
	}

	return se;
}

struct sip_session_expires_t * sip_session_expires_clone(apr_pool_t * pool, const struct sip_session_expires_t * src)
{
	struct sip_session_expires_t * se;

	se = apr_pcalloc(pool, sizeof(struct sip_session_expires_t));
	se->pool = pool;
	se->expires = src->expires;
	if (src->refresher) se->refresher = apr_pstrdup(pool, src->refresher);
	return se;
}

int  sip_session_expires_to_string(const struct sip_session_expires_t * se, char * buff, int len)
{
	int l = 0;
	l = apr_snprintf(buff, (apr_size_t)len, "%d", se->expires);

	if (se->refresher)
	{
		l += apr_snprintf(buff + l, (apr_size_t)(len - l), ";refresher=%s", se->refresher);
	}
	return l;
}

