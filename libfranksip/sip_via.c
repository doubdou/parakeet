#include "sip_via.h"



struct sip_via_t *  sip_via_make(apr_pool_t * pool)
{
	struct sip_via_t * via;
	via = apr_pcalloc(pool, sizeof(struct sip_via_t));
	via->pool = pool;
	via->params = sip_generic_param_make(pool);
	via->port = 5060;

	return via;
}

struct sip_via_t *  sip_via_parse(apr_pool_t * pool, char * buff)
{
	//解析...
	//Via: SIP/2.0/UDP 192.168.1.12:8394;branch=z9hG4bK-d87543-232610361-1--d87543-;rport
	//
	struct sip_via_t * via = NULL;
	const char * str = buff;

	const char * host = 0;
	const char * port = 0;
	apr_size_t host_len = 0;
	//apr_size_t port_len = 0;

	//检查SIP/
	
	if (0 != strncmp(buff, SIP_PROTOCOL_VERSION, sizeof(SIP_PROTOCOL_VERSION)-1))
		return NULL;
	buff += sizeof(SIP_PROTOCOL_VERSION) - 1;
	if (*buff != ' ')return NULL;
	buff++;

	via = sip_via_make(pool);

	host = buff;
	str = buff;
	while(*str)
	{
		if (';' == *str)
		{
			via->params = sip_generic_param_parse(pool, str + 1);
			break;
		}
		else if (':' == *str)
		{
			host_len = (apr_size_t)(str - host);
			str++;
			port = str;
		}
		else
		{
			str++;
		}
	}

	if (0 == host_len)
	{
		host_len = (apr_size_t)(str - host);
		if (0 == host_len)
			return NULL;
	}
	via->host = apr_pstrndup(via->pool, host, host_len);

	if (port)
	{
		via->port = atoi(port);
	}
	else
	{
		via->port = 5060;
	}
	
	return via;
}

struct sip_via_t *  sip_via_clone(apr_pool_t * pool, const struct sip_via_t * via)
{
	//复制
	struct sip_via_t * r;

	assert(via);
	assert(via->host);
	assert(via->port);
	assert(via->params);

	r = apr_pcalloc(pool, sizeof(struct sip_via_t));
	assert(r);
	r->pool = pool;
	r->host = apr_pstrdup(pool, via->host);
	r->port = via->port;
//	r->params = apr_hash_copy(pool, via->params);
	if (via->params) r->params = sip_generic_param_clone(pool, via->params);
	
	return r;
}

int sip_via_to_string(const struct sip_via_t * via, char * buff, int len)
{
	int l;

	assert( via );
	assert(via->host);
	assert(via->port);
	assert(via->params);

	if (5060 != via->port)
	{
		l = apr_snprintf(buff, (apr_size_t)len, SIP_PROTOCOL_VERSION " %s:%d", via->host, via->port);
	}
	else
	{
		l = apr_snprintf(buff, (apr_size_t)len, SIP_PROTOCOL_VERSION " %s", via->host);
	}

	//参数.
	l += sip_generic_param_to_string(via->params, buff + l, len - l);

	return l;
}

/*****
void sip_via_set_host(struct sip_via_t * via, const char * host)
{
	assert(via);
	assert(host);
	via->host = apr_pstrdup(via->pool, host);
}

const char * sip_via_get_host(const struct sip_via_t * via)
{
	assert(via);
	assert(via->host);	
	return via->host;
}

void sip_via_set_port(struct sip_via_t * via, int port)
{
	assert(via);
	assert(port);
	via->port = port;
}

int sip_via_get_port(const struct sip_via_t * via)
{
	assert(via);
	assert(via->port);
	return via->port;
}


int  sip_via_set_param(struct sip_via_t * via, const char * key, const char * value)
{
	assert(via);
	assert(via->params);
	assert(key);
	sip_generic_param_set(via->params, key, value);
	return 0;
}


const char * sip_via_get_param(const struct sip_via_t * via, const char * key)
{
	assert(via);
	assert(key);
	assert(via->params);
	return sip_generic_param_get(via->params, key);
}
*****/

int sip_via_match(const struct sip_via_t * via1, const struct sip_via_t * via2)
{
	assert(via1);
	assert(via2);

	assert(via1->host);
	assert(via1->port);
	assert(via2->host);
	assert(via2->port);

	
	if (via1->port == via2->port &&
		!apr_strnatcmp(via1->host, via2->host))
	{
		const char * branch1 = sip_via_get_branch(via1);
		const char * branch2 = sip_via_get_branch(via2);
		if ( branch1 && branch2 )
		{
			if (!apr_strnatcmp(branch1, branch2))
				return 0;
		}
	}
	return -1;
}

