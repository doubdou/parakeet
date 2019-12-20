#ifndef SIPVOICE_CONTACT_H
#define SIPVOICE_CONTACT_H

#include "sip_utils.h"
#include "sip_uri.h"
#include "sip_params.h"


struct sip_contact_t
{
	// Contact: lxf<sip:123456@host:port;arg=value>;arg=value

	char * displayname;	//若有该值, 则contact需要有尖括号
	struct sip_uri_t * uri;	// 里面包含内部参数
	//apr_hash_t * param;
	sip_paramlist_t * param;
	apr_pool_t * pool;
};


//理论上contact允许有多个, 但是此处我们仅处理一个.

struct sip_contact_t * sip_contact_make(apr_pool_t * pool);
struct sip_contact_t *  sip_contact_parse(apr_pool_t * pool, char * buff);
struct sip_contact_t *  sip_contact_clone(apr_pool_t * pool, const struct sip_contact_t * src);
int  sip_contact_to_string(const struct sip_contact_t * contact, char * buff, int len);
int  sip_contact_compare(const struct sip_contact_t * c1, const struct sip_contact_t * c2);

//void sip_contact_set_displayname(struct sip_contact_t *contact, const char * displayname);
#define sip_contact_set_displayname(c, s) c->displayname = (s)?apr_pstrdup(c->pool, s):0

//const char * sip_contact_get_displayname(const struct sip_contact_t *contact);
#define sip_contact_get_displayname(c) c->displayname

int sip_contact_set_username(struct sip_contact_t * contact, const char * username);

//const char * sip_contact_get_username(const struct sip_contact_t * contact);
#define sip_contact_get_username(c) ((c)->uri)?sip_uri_get_username((c)->uri):0

//int sip_contact_set_domain(struct sip_contact_t * contact, const char * host, int port);
#define sip_contact_set_domain(c, h,p) if(0==c->uri) c->uri=sip_uri_make(c->pool); sip_uri_set_domain(c->uri,h,p)

//const char * sip_contact_get_host(const struct sip_contact_t * contact);
#define sip_contact_get_host(c)  ((c)->uri) ? sip_uri_get_host((c)->uri):0

//int sip_contact_get_port(const struct sip_contact_t * contact);
#define sip_contact_get_port(c) ((c)->uri)? sip_uri_get_port((c)->uri):0

void sip_contact_set_param(struct sip_contact_t *contact, const char * key, const char * value);
//const char * sip_contact_get_param(const struct sip_contact_t *contact, const char * key);
#define sip_contact_get_param(c, k) (c->param)?sip_generic_param_get(c->param,k):0

#define sip_contact_get_tag(contact) sip_contact_get_param(contact, "tag")
#define sip_contact_set_tag(contact, taget) sip_contact_set_param(contact,"tag",taget)

#define sip_contact_set_expires(contact, val) sip_contact_set_param(contact,"expires",val)
#define sip_contact_get_expires(contact) sip_contact_get_param(contact,"expires")

#endif

