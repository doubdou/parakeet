#include "sip_route.h"



struct sip_route_t * sip_route_make(apr_pool_t * pool)
{
	struct sip_route_t * tmp = apr_pcalloc(pool, sizeof(struct sip_route_t));
	tmp->pool = pool;
	return tmp;
}

struct sip_route_t * sip_route_parse(apr_pool_t * pool, char * buff)
{
	// <sip:p2.example.com;lr> 
	// <sip:p2.example.com;lr>,<sip:p2.example.com;lr> 
	char * str = 0;
	struct sip_route_t * tmp = 0;
	struct sip_route_t * route = 0, *tail = 0;

	while ('<' == *buff)
	{
		buff++;
		if (strncmp(buff, "sip:", 4))
			break;
		buff += 4;

		str = strchr(buff, '>');
		if (NULL == str) break;
		*str = 0;
		str++;

		tmp = apr_pcalloc(pool, sizeof(struct sip_route_t));
		tmp->pool = pool;
		tmp->domain = apr_pstrdup(pool, buff);
		tmp->lr = strrchr(tmp->domain, ';');
		if (tmp->lr)
		{
			*tmp->lr = 0;
			tmp->lr++;
		}

		if (0 == tail)
		{
			route = tmp;
		}
		else
		{
			tail->next = tmp;
		}
		tail = tmp;

		buff = str;
		if (',' == *buff) buff++;
	}
	return route;
}

struct sip_route_t * sip_route_clone(apr_pool_t * pool, struct sip_route_t * src)
{
	struct sip_route_t * tmp = apr_pcalloc(pool, sizeof(struct sip_route_t));
	assert(src);
	assert(src->domain);
	tmp->pool = pool;
	tmp->domain = apr_pstrdup(pool, src->domain);
	if (src->lr) tmp->lr = apr_pstrdup(pool, src->lr);

	return tmp;
}

int sip_route_tostring(const struct sip_route_t * route, char * buff, int len)
{
	if (route->lr)
	{
		return apr_snprintf(buff, (apr_size_t)len, "<sip:%s;lr>", route->domain);
	}
	else
	{
		return apr_snprintf(buff, (apr_size_t)len, "<sip:%s>", route->domain);
	}
}

