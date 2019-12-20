#ifndef SIPVOICE_CONTENT_TYPE_H
#define SIPVOICE_CONTENT_TYPE_H

#include "sip_utils.h"


struct sip_content_type_t
{
	apr_pool_t * pool;
	char *		 type;
	char *		 params;
};

struct sip_content_type_t * sip_content_type_make(apr_pool_t * pool);
struct sip_content_type_t * sip_content_type_parse(apr_pool_t * pool, const char * buff);
struct sip_content_type_t * sip_content_type_clone(apr_pool_t * pool, const struct sip_content_type_t * src);
int  sip_content_type_to_string(const struct sip_content_type_t * cnt, char * buff, int len);

//int  sip_content_type_set_type(struct sip_content_type_t * cnt, const char * type);
#define sip_content_type_set_type(cnt,t) cnt->type=t?apr_pstrdup(cnt->pool,t):0

//int  sip_content_type_set_param(struct sip_content_type_t * cnt, const char * param);
#define sip_content_type_set_param(cnt, p) cnt->params=p?apr_pstrdup(cnt->pool,p):0


//int  sip_content_type_compare(const struct sip_content_type_t * cnt, const char * type);
#define sip_content_type_compare(cnt, t) cnt->type?apr_strnatcmp(cnt->type, t):-1

//const char * sip_content_type_get_type(const struct sip_content_type_t * cnt);
#define sip_content_type_get_type(cnt) cnt->type

//const char * sip_content_type_get_param(const struct sip_content_type_t * cnt);
#define sip_content_type_get_param(cnt) cnt->params

//const char * sip_content_get_length(const struct sip_content_type_t * cnt);



#endif
