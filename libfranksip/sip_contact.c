#include "sip_contact.h"

struct sip_contact_t * sip_contact_make(apr_pool_t * pool)
{
	struct sip_contact_t * tmp = (struct sip_contact_t *)apr_pcalloc(pool, sizeof(struct sip_contact_t));
	assert(tmp);

	tmp->pool = pool;
	
	return tmp;
}

struct sip_contact_t *  sip_contact_parse(apr_pool_t * pool, char * buff)
{
	//解析Contact.
	// "lxf" <sip:13987654321@192.168.1.12:8394;transport=udp>;expires=3600
	//允许没有尖括号.
	//首先解析uri.
	//类似contact.
	
	//查找displayname, 注意删除空格和制表符
	struct sip_contact_t * contact = sip_contact_make(pool);
	char * str, *tmp;
	
	//如果是 * 号.
	if ( buff[0] == '*' && buff[1] == '\0' )
	{
		contact->displayname = "*";
		return contact;
	}

	str = strchr(buff, '<');
	if (str)
	{
		const char * displayname;
		*str = 0;

		displayname = buff;
		if (*displayname == '"')
		{
			displayname++;
			tmp = strchr(displayname, '"');
			if (0 == tmp)return NULL;
			*tmp = 0;
		}
		else
		{
			tmp = str;
			tmp--;
			while (' ' == *tmp)tmp--;
			tmp++;
			*tmp = 0;
		}

		if(*displayname)
		{
			contact->displayname = apr_pstrdup(pool, displayname);
		}

		buff = str;
		buff++;

		str = strchr(buff, '>');
		if (NULL == str)return NULL;
		*str = 0;

		contact->uri = sip_uri_parse(pool, buff);
		if (NULL == contact->uri)return NULL;

		str++;
		if (';' == *str)
		{
			str++;
			contact->param = sip_generic_param_parse(pool, str);
		}
	}
	else
	{
		str = strchr(buff, ';');
		if (str)
		{
			*str = 0;
			str++;
			contact->param = sip_generic_param_parse(pool, str);
		}
		contact->uri = sip_uri_parse(pool, buff);
		if (NULL == contact->uri)return NULL;
	}

	return contact;
}

struct sip_contact_t *  sip_contact_clone(apr_pool_t * pool, const struct sip_contact_t * src)
{
	//复制一个contact
	struct sip_contact_t * tmp;
	
	if (NULL == src || NULL == src->uri)
		return NULL;
	
	tmp = sip_contact_make(pool);

	if (src->displayname)
	{
		tmp->displayname = apr_pstrdup(pool, src->displayname);
	}

	tmp->uri = sip_uri_clone(pool, src->uri);
	if (NULL == tmp->uri)return NULL;

	if (src->param)
	{
		tmp->param = sip_generic_param_clone(pool, src->param);
	}
	return tmp;
}


int  sip_contact_to_string(const struct sip_contact_t * contact, char * buff, int len)
{
	int l = 0;

	assert(contact);
	assert(contact->uri);

	if (NULL == contact->uri)return 0;

	if (contact->displayname)
	{
		if ( contact->displayname[0] == '*' )
		{
			buff[0] = '*';
			return 1;
		}

		l = apr_snprintf(buff, (apr_size_t)len, "\"%s\" ", contact->displayname);
	}

	//额外加上一对尖括号
	assert( NULL != contact->uri );
	buff[l++] = '<';
	l += sip_uri_to_string(contact->uri, buff + l, len - l);
	buff[l++] = '>';

	//后续的参数.
	//参数.
	if (contact->param)
	{
		l += sip_generic_param_to_string(contact->param, buff + l, len - l);
	}

	return l;
}

int  sip_contact_compare(const struct sip_contact_t * c1, const struct sip_contact_t * c2)
{
	assert(c1);
	assert(c2);
	assert(c1->uri);
	assert(c2->uri);

	if (NULL == c1->uri || NULL == c2->uri)
		return -1;

	if (!apr_strnatcmp(sip_uri_get_host(c1->uri), sip_uri_get_host(c2->uri)) &&
		sip_uri_get_port(c1->uri) == sip_uri_get_port(c2->uri))
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

/**
void sip_contact_set_displayname(struct sip_contact_t *contact, const char * displayname)
{
	assert(contact);
	if (displayname && *displayname)
	{
		contact->displayname = apr_pstrdup(contact->pool, displayname);
	}
	else contact->displayname = NULL;
}

const char * sip_contact_get_displayname(const struct sip_contact_t *contact)
{
	assert(contact);
	return contact->displayname;
}
**/

int sip_contact_set_username(struct sip_contact_t * contact, const char * username)
{
	if (username && *username)
	{
		if (NULL == contact->uri)
		{
			contact->uri = sip_uri_make(contact->pool);
			if (NULL == contact->uri)return -1;
		}
		sip_uri_set_username(contact->uri, username);
	}
	else
	{
		if (contact->uri)
		{
			sip_uri_set_username(contact->uri, 0);
		}
	}
	return 0;
}

/***
const char * sip_contact_get_username(const struct sip_contact_t * contact)
{
	assert(contact);
	assert(contact->uri);

	if (NULL == contact->uri)return NULL;
	return sip_uri_get_username(contact->uri);
}


int sip_contact_set_domain(struct sip_contact_t * contact, const char * host, int port)
{
	if ( NULL == contact->uri )
	{
		contact->uri = sip_uri_make(contact->pool);
		if (NULL == contact->uri)return -1;
	}

	sip_uri_set_domain(contact->uri, host, port);
	return 0;
}

const char * sip_contact_get_host(const struct sip_contact_t * contact)
{
	assert(contact);
	assert(contact->uri);
	if ( NULL == contact || NULL == contact->uri ) return NULL;
	return sip_uri_get_host(contact->uri);
}

int sip_contact_get_port(const struct sip_contact_t * contact)
{
	assert(contact);
	assert(contact->uri);
	if ( NULL == contact || NULL == contact->uri ) return 0;
	return sip_uri_get_port(contact->uri);
}
***/


void sip_contact_set_param(struct sip_contact_t *contact, const char * key, const char * value)
{
	if (value)
	{
		if (NULL == contact->param)
		{
			contact->param = sip_generic_param_make(contact->pool);
			assert(contact->param);
		}
		sip_generic_param_set(contact->param, key, value);
	}
	else
	{
		if (contact->param)
		{
			sip_generic_param_set(contact->param, key, 0);
		}
	}
}

/**
const char * sip_contact_get_param(const struct sip_contact_t *contact, const char * key)
{
	assert(contact);
	if (NULL == contact->param)return NULL;
	return sip_generic_param_get(contact->param, key);
}
**/

