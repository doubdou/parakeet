#include "sip_www_authenticate.h"


struct sip_www_authenticate_t * sip_www_authenticate_make(apr_pool_t * pool)
{
	struct sip_www_authenticate_t * auth;
	auth = apr_pcalloc(pool, sizeof(struct sip_www_authenticate_t));
	assert(auth);
	auth->pool = pool;
	return auth;
}


struct sip_www_authenticate_t * sip_www_authenticate_parse(apr_pool_t * pool, char * buff)
{
	/*
	WWW-Authenticate: Digest realm="00c10b587722fc4ad9a5f58b0c0f37fe", nonce="00c10b587722fc4ad9a5f58b0c0f37fe", opaque="", algorithm=MD5, qop="auth"
	Authorization: Digest username="8001",realm="00c10b587722fc4ad9a5f58b0c0f37fe",nonce="00c10b587722fc4ad9a5f58b0c0f37fe",uri="sip:192.168.1.105;transport=udp",response="8b4a141de0f69b272605d95434b5ec49",cnonce="8967fa4d9a33c10f",nc=00000001,qop=auth,algorithm=MD5,opaque=""

	WWW-Authenticate: Digest realm="10.250.250.116", nonce="59f60a1a-de81-11e8-93ef-812c77c38bb9", algorithm=MD5, qop="auth"
	*/
	const char * key = 0;
	const char * value = 0;
	apr_size_t klen = 0;
	apr_size_t vlen = 0;
	const char * str;

	struct sip_www_authenticate_t * auth;
	
	if ( 0 != strncmp("Digest ", buff, 7) )
		return NULL;
	buff += 7;

	auth = sip_www_authenticate_make(pool);

	key = buff;
	while (key)
	{
		while (' ' == *key)key++;
		str = strchr(key, '=');
		if (0 == str)break;
		klen = (apr_size_t)(str - key);
		str++;
		value = str;
		str = strchr(value, ',');
		if (str)
		{
			vlen = (apr_size_t)(str - value);
			str++;
		}
		else
		{
			vlen = strlen(value);
		}
		if ('"' == *value)
		{
			value++;
			vlen--;
			vlen--;
		}

		if (strncmp(key, "realm", klen) == 0) auth->realm = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "domain", klen) == 0) auth->domain = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "nonce", klen) == 0) auth->nonce = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "opaque", klen) == 0) auth->opaque = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "stale", klen) == 0) auth->stale = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "algorithm", klen) == 0) auth->algorithm = apr_pstrndup(pool, value, vlen);
		else if (strncmp(key, "qop", klen) == 0) auth->qop_options = apr_pstrndup(pool, value, vlen);

		key = str;

		/*****
		if ('=' == *str)
		{ // 如果字段值中有等于号, 这里判断是有问题的. 例如: uri="sip:10.250.251.32;transport=udp" 这种.
			klen = (apr_size_t)(str - key);
			str++;
			value = str;
		}
		else if (',' == *str || '\0' == *str)
		{
			if (NULL == value)return NULL;

			if ('"' == *value)
			{
				value++;
				vlen = (apr_size_t)(str - value);
				vlen--;
				if ('"' != value[vlen])
					return NULL;
			}
			else
			{
				vlen = (apr_size_t)(str - value);
			}

			if (strncmp(key, "realm", klen) == 0) auth->realm = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "domain", klen) == 0) auth->domain = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "nonce", klen) == 0) auth->nonce = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "opaque", klen) == 0) auth->opaque = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "stale", klen) == 0) auth->stale = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "algorithm", klen) == 0) auth->algorithm = apr_pstrndup(pool, value, vlen);
			else if (strncmp(key, "qop", klen) == 0) auth->qop_options = apr_pstrndup(pool, value, vlen);

			if ('\0' == *str) break;
			str++;
			while (' ' == *str)str++;
			key = str;
			value = 0;
		}
		else
		{
			str++;
		}
		****/
	}
	
	return auth;
}


struct sip_www_authenticate_t * sip_www_authenticate_clone(apr_pool_t * pool, const struct sip_www_authenticate_t * src)
{
	struct sip_www_authenticate_t * tmp;
//	char * name1, * name2;
//	char * value1, * value2;
//	int i;
	//typedef char * pointer;
	//pointer * name = (pointer *) src;

	assert( NULL != src );
	tmp = sip_www_authenticate_make(pool);
	assert(tmp);

	if (src->realm) tmp->realm = apr_pstrdup(pool, src->realm);
	if (src->domain) tmp->domain = apr_pstrdup(pool, src->domain);
	if (src->nonce) tmp->nonce = apr_pstrdup(pool, src->nonce);
	if (src->opaque) tmp->opaque = apr_pstrdup(pool, src->opaque);
	if (src->stale) tmp->stale = apr_pstrdup(pool, src->stale);
	if (src->algorithm) tmp->algorithm = apr_pstrdup(pool, src->algorithm);
	if (src->qop_options) tmp->qop_options = apr_pstrdup(pool, src->qop_options);
	if (src->auth_param) tmp->auth_param = apr_pstrdup(pool, src->auth_param);

	if ( (src->algorithm && tmp->algorithm == 0) ||
		(src->auth_param && tmp->auth_param == 0 ) ||
		(src->domain && tmp->domain == 0 ) ||
		(src->nonce && tmp->nonce == 0 ) ||
		(src->opaque && tmp->opaque == 0 ) ||
		(src->qop_options && tmp->qop_options ==0 )||
		(src->realm && tmp->realm == 0 ) ||
		(src->stale && tmp->stale ==0 ) )
	{
	//	sip_www_authenticate_free(tmp);
		return NULL;
	}

	return tmp;
}

int  sip_www_authenticate_to_string(const struct sip_www_authenticate_t * auth, char * buff, int size)
{
	int len;
	//char * tmp;

	assert( NULL != auth );

	len = apr_snprintf(buff, (apr_size_t)size, "Digest");
//	strcpy(buff, "Digest");
//	len = 6;//sprintf(buff, "%s", auth->auth_type);
//	//tmp = (char *) (buff+len);
//	assert(len == strlen(buff));

	if ( auth->realm )
	{
		len += apr_snprintf(buff+len, (apr_size_t)(size-len), " realm=\"%s\",", auth->realm);
	}
	if ( auth->domain )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " domain=\"%s\",", auth->domain);
	}
	if ( auth->nonce )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " nonce=\"%s\",", auth->nonce);
	}
	if ( auth->opaque )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " opaque=\"%s\",", auth->opaque);
	}

	if ( auth->stale )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " stale=%s,", auth->stale);
	}
	if ( auth->algorithm )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " algorithm=%s,", auth->algorithm);
	}
	if ( auth->qop_options )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " qop=\"%s\",", auth->qop_options);
	}
	// 0,
	len --;
	if ( buff[len] == ',') buff[len] = 0;
	//if ( tmp[0] != ' ') tmp[0] = ' ';

	return len;
}

void sip_www_authenticat_set(struct sip_www_authenticate_t * auth, const char * nonce, const char * realm)
{
	assert( NULL == auth->nonce );
	assert( NULL == auth->realm );
	assert( NULL == auth->algorithm );
	assert( NULL == auth->opaque );
	assert( NULL == auth->qop_options );

	auth->nonce = apr_pstrdup(auth->pool, nonce);
	auth->realm = apr_pstrdup(auth->pool, realm);
	auth->algorithm = "MD5";
	// 始终设置了qop. 那么使用要返回opaque.
	auth->qop_options = "auth";
	auth->opaque = NULL;
}


