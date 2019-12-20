#include "sip_params.h"


sip_paramlist_t * sip_generic_param_make(apr_pool_t * pool)
{
	sip_paramlist_t * node = (sip_paramlist_t *)apr_pcalloc(pool, sizeof(sip_paramlist_t));
	node->pool = pool;
	return node;
}

void sip_generic_param_set(sip_paramlist_t * params, const char * key, const char * value)
{
	sip_paramnode_t * ptr = params->head;
	if (value)
	{
		// 赋值.
		while (ptr)
		{
			if (!apr_strnatcmp(key, ptr->key))
			{
				break;
			}
			ptr = ptr->next;
		}

		if (NULL == ptr)
		{
			ptr = (sip_paramnode_t *)apr_pcalloc(params->pool, sizeof(sip_paramnode_t));
			ptr->key = apr_pstrdup(params->pool, key);
			ptr->next = NULL;
			if (params->tail)
			{
				params->tail->next = ptr;
			}
			else
			{
				params->head = ptr;
			}
			params->tail = ptr;
		}

		ptr->value = apr_pstrdup(params->pool, value);
	}
	else
	{
		// 删除.
		sip_paramnode_t * prev = 0;
		while (ptr)
		{
			if (!apr_strnatcmp(key, ptr->key))
			{
				if (prev)prev->next = ptr->next;
				else params->head = ptr->next;

				break;
			}
			prev = ptr;
			ptr = ptr->next;
		}
	}
}

void sip_generic_param_add(sip_paramlist_t * params, const char * key, apr_size_t klen, const char * value, apr_size_t vlen)
{
	sip_paramnode_t * ptr;

	assert(params);
	assert(NULL == sip_generic_param_get(params, key));

	ptr = (sip_paramnode_t *)apr_pcalloc(params->pool, sizeof(sip_paramnode_t));
	ptr->next = NULL;
	if (params->tail)
	{
		params->tail->next = ptr;
	}
	else
	{
		params->head = ptr;
	}
	params->tail = ptr;

	ptr->key = apr_pstrndup(params->pool, key, klen);
	if (vlen == 0)
	{
		ptr->value = NULL;
	}
	else
	{
		ptr->value = apr_pstrndup(params->pool, value, vlen);
	}
}

#if 0
void sip_generic_param_set(apr_pool_t *pool, apr_hash_t * params, const char * key, const char * value)
{
	assert(pool);
	assert(params);
	assert(key);
	assert(value);

	apr_hash_set(params, apr_pstrdup(pool, key), APR_HASH_KEY_STRING, apr_pstrdup(pool, value));
}
#endif


const char * sip_generic_param_get(sip_paramlist_t * params, const char * key)
{
	sip_paramnode_t * ptr = params->head;
	while (ptr)
	{
		if (!apr_strnatcmp(key, ptr->key))
		{
			break;
		}
		ptr = ptr->next;
	}
	return ptr ? ptr->value : NULL;
}

#if 0
const char * sip_generic_param_get(apr_hash_t * params, const char * key)
{
	assert(params);
	assert(key);
	return apr_hash_get(params, key, APR_HASH_KEY_STRING);
}
#endif

sip_paramlist_t *  sip_generic_param_clone(apr_pool_t * pool, const sip_paramlist_t * params)
{
	sip_paramnode_t * node = 0;
	sip_paramnode_t * ptr;
	sip_paramlist_t * tmp;

	if (NULL == params) return NULL;

	ptr = params->head;
	tmp = (sip_paramlist_t *)apr_pcalloc(pool, sizeof(sip_paramlist_t));
	tmp->pool = pool;

	while (ptr)
	{
		node = (sip_paramnode_t *)apr_palloc(pool, sizeof(sip_paramnode_t));
		node->key = apr_pstrdup(pool, ptr->key);
		if (ptr->value)
		{
			node->value = apr_pstrdup(pool, ptr->value);
		}
		else
		{
			node->value = NULL;
		}

		if (tmp->tail)
		{
			tmp->tail->next = node;
		}
		else
		{
			tmp->head = node;
		}
		tmp->tail = node;

		ptr = ptr->next;
	}
	if (tmp->tail) tmp->tail->next = NULL;

	return tmp;
}

#if 0
apr_hash_t *  sip_generic_param_clone(apr_pool_t * pool, const apr_hash_t * params)
{
	if(params) return apr_hash_copy(pool, params);
	else return NULL;
}
#endif

sip_paramlist_t * sip_generic_param_parse(apr_pool_t * pool, const char * str)
#if 0
apr_hash_t * sip_generic_param_parse(apr_pool_t * pool, const char * str)
#endif
{
	// 解析参数
	//
	const char * key = str;
	const char * value = 0;
	// char completed = 0;

	apr_size_t klen = 0;
	apr_size_t vlen = 0;

	sip_paramlist_t * h = sip_generic_param_make(pool);
//	apr_hash_t * h = apr_hash_make(pool);

	// a = b; a;
	assert(*str != ';');

	while (*str)
	{
		if (';' == *str)
		{
			if (value)
			{
				assert(klen);
				assert(*key);
				vlen = (apr_size_t)(str - value);
				if (vlen && klen)
				{
					//apr_hash_set(h, apr_pstrndup(pool, key, klen), klen, apr_pstrndup(pool, value, vlen));
					sip_generic_param_add(h, key, klen, value, vlen);
				}
			}
			else
			{
				klen = (apr_size_t)(str - key);
				if (klen)
				{
					//apr_hash_set(h, apr_pstrndup(pool, key, klen), klen, "");
					sip_generic_param_add(h, key, klen, NULL, 0);
				}
			}

			str++;
			key = str;
			value = 0;
			klen = 0;
			vlen = 0;
		}
		else if ('=' == *str)
		{
			klen = (apr_size_t)(str - key);
			str++;
			value = str;
		}
		else
		{
			assert(*str != '\r');
			assert(*str != '\n');
			assert(*str != '\0');
			str++;
		}
	}

	if (key)
	{
		if (value)
		{
			sip_generic_param_add(h, key, klen, value, (apr_size_t)strlen(value));
			//apr_hash_set(h, apr_pstrndup(pool, key, klen), klen, apr_pstrdup(pool, value));
		}
		else
		{
			sip_generic_param_add(h, key, (apr_size_t)strlen(key), NULL, 0);
			//apr_hash_set(h, apr_pstrdup(pool, key), APR_HASH_KEY_STRING, "");
		}
	}

	return h;
}


int  sip_generic_param_to_string(const sip_paramlist_t * params, char * buff, int len)
{
	sip_paramnode_t * node = params->head;
	int l = 0;
	while (node)
	{
		if (node->value)
		{
			l += apr_snprintf(buff + l, (apr_size_t)(len - l), ";%s=%s", node->key, node->value);
		}
		else
		{
			l += apr_snprintf(buff + l, (apr_size_t)(len - l), ";%s", node->key);
		}
		node = node->next;
	}
	return l;
}

#if 0
int  sip_generic_param_to_string(const apr_hash_t * params, char * buff, int len)
{
	apr_hash_index_t * hi;
	char * key;
	char * val;
	int l = 0;

	for (hi = apr_hash_first(0, (apr_hash_t*)params); hi; hi = apr_hash_next(hi))
	{
		apr_hash_this(hi, (void**)&key, 0, (void**)&val);
		if (*val)
		{
			l += apr_snprintf(buff + l, len - l, ";%s=%s", key, val);
		}
		else
		{
			l += apr_snprintf(buff + l, len - l, ";%s", key);
		}
	}

	return l;
}
#endif

