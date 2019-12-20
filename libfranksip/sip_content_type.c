#include "sip_content_type.h"



struct sip_content_type_t * sip_content_type_make(apr_pool_t * pool)
{
	struct sip_content_type_t * tmp = (struct sip_content_type_t *)apr_pcalloc(pool,sizeof(struct sip_content_type_t));
	
	assert(tmp);
	tmp->pool = pool;

	return tmp;
}


struct sip_content_type_t * sip_content_type_parse(apr_pool_t * pool, const char * buff)
{
	struct sip_content_type_t * cnt = sip_content_type_make(pool);
	const char * str;

	assert(*buff != ' ');

	str = strchr(buff, ';');
	if (str)
	{
		cnt->type = apr_pstrndup(pool, buff, (apr_size_t)(str - buff));
		str++;
		cnt->params = apr_pstrdup(pool, str);
	}
	else
	{
		cnt->type = apr_pstrdup(pool, buff);
	}

	return cnt;
}


struct sip_content_type_t * sip_content_type_clone(apr_pool_t * pool, const struct sip_content_type_t * src)
{
	struct sip_content_type_t * cnt = sip_content_type_make(pool);
	assert(src);
	assert(src->type);
	cnt->type = apr_pstrdup(pool, src->type);
	if (src->params)cnt->params = apr_pstrdup(pool, src->params);
	return cnt;
}

/***
int  sip_content_type_set_type(struct sip_content_type_t * cnt, const char * type)
{
	if (type&&*type)
	{
		cnt->type = apr_pstrdup(cnt->pool, type);
	}
	else
	{
		cnt->type = 0;
	}
	return 0;
}

int  sip_content_type_set_param(struct sip_content_type_t * cnt, const char * param)
{
	if (param && *param)
	{
		cnt->params = apr_pstrdup(cnt->pool, param);
	}
	else
	{
		cnt->params = 0;
	}
	return 0;
}
***/

int  sip_content_type_to_string(const struct sip_content_type_t * cnt, char * buff, int len)
{
	int l = 0;

	assert(cnt);
	assert(cnt->type);

	if (cnt->params)
	{
		l = apr_snprintf(buff, (apr_size_t)len, "%s;%s", cnt->type, cnt->params);
	}
	else
	{
		l = apr_snprintf(buff, (apr_size_t)len, "%s", cnt->type);
	}
	return l;
}

/***
int  sip_content_type_compare(const struct sip_content_type_t * cnt, const char * type)
{
	if (NULL == cnt->type)return -1;
	return apr_strnatcmp(cnt->type, type);
}

const char * sip_content_type_get_type(const struct sip_content_type_t * cnt)
{
	assert(cnt);
	return cnt->type;
}

const char * sip_content_type_get_param(const struct sip_content_type_t * cnt)
{
	assert(cnt);
	return cnt->params;
}
***/


