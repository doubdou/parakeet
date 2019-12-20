#include "sip_uri.h"


struct sip_uri_t *  sip_uri_make(apr_pool_t * pool)
{
	struct sip_uri_t * uri = (struct sip_uri_t *)apr_pcalloc(pool, sizeof(struct sip_uri_t));
	assert(uri);
	uri->pool = pool;

	return uri;
}

struct sip_uri_t* sip_uri_parse(apr_pool_t* pool, char* buff)
{
	//解析一个uri
	//解析 uri, 其中尖括号是可选的.
	//尾部和头部不能有空格.
	//参数buff为需要解析的字符串, size为该字符串的长度, 如果为-1则由本函数自己获取长度.
	//如下格式是正确的
	/*
	sip:j.doe@big.com;maddr=239.255.255.1;ttl=15
	sip:j.doe@big.com
	sip:j.doe:secret@big.com;transport=tcp
	sip:j.doe@big.com?subject=project
	sip:+1-212-555-1212:1234@gateway.com;user=phone
	sip:1212@gateway.com
	sip:alice@10.1.2.3
	sip:alice@example.com
	sip:alice@registrar.com;method=REGISTER
	sip:callbay.com

	NOT EQUIVALENT:
	SIP:JUSER@ExAmPlE.CoM;Transport=udp
	sip:juser@ExAmPlE.CoM;Transport=UDP
	*/


	char* str;
	struct sip_uri_t* uri;

	//比较协议类型.
	if (strncmp(buff, "sip:", 4) != 0)
		return NULL;
	buff += 4;

	uri = sip_uri_make(pool);
	assert(uri);

	str = strchr(buff, '@');
	if (str)
	{
		*str = 0;
		uri->username = apr_pstrdup(pool, buff);
		str++;
		buff = str;
	}


	str = strchr(buff, ';');
	if (str)
	{
		*str = 0;
		str++;

		uri->params = sip_generic_param_parse(uri->pool, str);
	}

	str = strchr(buff, ':');
	if (str)
	{
		*str = 0;
		uri->host = apr_pstrdup(pool, buff);
		str++;
		uri->port = atoi(str);
	}
	else
	{
		uri->host = apr_pstrdup(pool, buff);
		uri->port = 5060;
	}

	return uri;
}


struct sip_uri_t *  sip_uri_clone(apr_pool_t * pool, const struct sip_uri_t * src)
{
	struct sip_uri_t * uri;
	
	assert(src);
	if (NULL == src)return NULL;

	uri = (struct sip_uri_t*)apr_pcalloc(pool, sizeof(struct sip_uri_t));
	assert(uri);
	uri->pool = pool;

	if (src->username) uri->username = apr_pstrdup(pool,src->username);
//	if (src->password) uri->password = apr_pstrdup(pool, src->password);
	if (src->host) uri->host = apr_pstrdup(pool, src->host);
	uri->port = src->port;
	uri->params = sip_generic_param_clone(pool, src->params);

	return uri;
}

int  sip_uri_to_string(const struct sip_uri_t * uri, char * buff, int len)
{
	//将uri转换为字符串.无尖括号.
	//例如: sip:8765:password@callbay.com.cn:5070
	//返回长度.
	int l = 0;

	assert(uri);
	

	if ( uri->username ) 
	{
		assert(*uri->username !=0);
	//	if (uri->password)
	//		l = apr_snprintf(buff, len, "sip:%s:%s@", uri->username, uri->password);
	//	else
	//	if (uri->is_gateway)
	//	{
	//		l = apr_snprintf(buff, len, "sip:gw+%s@", uri->username);
	//	}
	//	else
	//	{
			l = apr_snprintf(buff, (apr_size_t)len, "sip:%s@", uri->username);
	//	}
	}
	
	assert(uri->host);
	if ( uri->host ) 
	{
		if( 0 == uri->port || 5060 == uri->port)
		{
			l += apr_snprintf(buff + l, (apr_size_t)(len - l), "%s", uri->host);
		}
		else
		{
			l += apr_snprintf(buff + l, (apr_size_t)(len - l), "%s:%d", uri->host, uri->port);
		}
	}

	//参数.
	if (uri->params)
	{
		l += sip_generic_param_to_string(uri->params, buff + l, len - l);
	}

//	if (uri->is_gateway && uri->username)
//	{
//		l += apr_snprintf(buff + l, len - l, ";gw=%s", uri->username);
//	}

	return l;
}

/****
void sip_uri_set_username(struct sip_uri_t * uri, const char * username)
{
	assert(uri);
	assert(username);

	if (username && *username) uri->username = apr_pstrdup(uri->pool, username);
	else uri->username = 0;
}

void sip_uri_set_password(struct sip_uri_t * uri, const char * password)
{
	assert(uri);
	
	if (password && *password) uri->password = apr_pstrdup(uri->pool, password);
	else uri->password = 0;
}

void sip_uri_set_domain(struct sip_uri_t * uri, const char * host, int port)
{
	assert(uri);
	assert(host);
	assert(port);

	uri->host = apr_pstrdup(uri->pool, host);
	uri->port = port;
}
***/

/****
const char * sip_uri_get_username(struct sip_uri_t * uri)
{
	assert(uri);
	return uri->username;
}

const char * sip_uri_get_password(struct sip_uri_t * uri)
{
	assert(uri);
	return uri->password;
}

const char * sip_uri_get_host(struct sip_uri_t * uri)
{
	assert(uri);
	assert(uri->host);
	return uri->host;
}

int sip_uri_get_port(struct sip_uri_t * uri)
{
	assert(uri);
	assert(uri->port);
	return uri->port;
}
***/

/**
void sip_uri_set_param(struct sip_uri_t * uri, const char * key, const char * value)
{
	if (NULL == uri->params)
	{
		uri->params = sip_generic_param_make(uri->pool);
	}
	sip_generic_param_set(uri->params, key, value);
}

const char * sip_uri_get_param(struct sip_uri_t * uri, const char * key)
{
	if (NULL == uri->params)
		return NULL;
	return sip_generic_param_get(uri->params, key);
}
**/


