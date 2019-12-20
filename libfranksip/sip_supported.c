#include "sip_supported.h"


struct sip_supported_t * sip_supported_make(apr_pool_t * pool)
{
	struct sip_supported_t * sup = apr_pcalloc(pool, sizeof(struct sip_supported_t));
	sup->pool = pool;
	sup->events = apr_hash_make(pool);
	return sup;
}

struct sip_supported_t * sip_supported_parse(apr_pool_t * pool, const char * buff)
{
	const char * str;
	char * evt;
	struct sip_supported_t * sup = sip_supported_make(pool);

	while (buff)
	{
		str = strchr(buff, ',');
		if (str)
		{
			apr_size_t l = (apr_size_t)(str - buff);
			evt = apr_pstrndup(pool, buff, l);
			apr_hash_set(sup->events, evt, (apr_ssize_t)l, evt);
			str++;
			while (' ' == *str)str++;
		}
		else
		{
			evt = apr_pstrdup(pool, buff);
			apr_hash_set(sup->events, evt, APR_HASH_KEY_STRING, evt);
		}
		buff = str;
	}
	return sup;
}

struct sip_supported_t * sip_supported_clone(apr_pool_t * pool, const struct sip_supported_t * src)
{
	struct sip_supported_t * sup = apr_pcalloc(pool, sizeof(struct sip_supported_t));
	sup->events = apr_hash_copy(pool, src->events);
	sup->pool = pool;
	return sup;
}

int sip_supported_to_string(const struct sip_supported_t * sup, char * buff, int len)
{
	apr_hash_index_t * hi;
	int l = 0;
	for (hi = apr_hash_first(0, sup->events); hi; hi = apr_hash_next(hi))
	{
		const char * str = apr_hash_this_val(hi);
		l += apr_snprintf(buff + l, (apr_size_t)(len - l), "%s, ", str);
	}
	if (l >= 2)l -= 2;

	return l;
}

int  sip_supported_exists(const struct sip_supported_t * sup, const char * evt)
{
	if (0 == sup->events) return 0;

	if (apr_hash_get(sup->events, evt, APR_HASH_KEY_STRING))
	{
		return 1;
	}
	return 0;
}

void sip_supported_insert(const struct sip_supported_t * sup, const char * evt)
{
	const char * str = apr_pstrdup(sup->pool, evt);
	assert(sup->events);
	apr_hash_set(sup->events, str, APR_HASH_KEY_STRING, str);
}

void sup_supported_remove(const struct sip_supported_t * sup, const char * evt)
{
	assert(sup->events);
	apr_hash_set(sup->events, evt, APR_HASH_KEY_STRING, 0);
}

