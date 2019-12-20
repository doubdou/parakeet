#ifndef SIPVOICE_CSEQ_H
#define SIPVOICE_CSEQ_H

#include "sip_utils.h"

struct sip_cseq_t
{
	apr_pool_t * pool;
	char * cseq_method;
	apr_uint32_t cseq_number;
};


struct sip_cseq_t * sip_cseq_make(apr_pool_t * pool);
struct sip_cseq_t * sip_cseq_parse(apr_pool_t * pool, const char * buff);
struct sip_cseq_t * sip_cseq_clone(apr_pool_t * pool, const struct sip_cseq_t * src);
int  sip_cseq_to_string(const struct sip_cseq_t * cseq, char * buff, int len);

//void sip_cseq_set_number(struct sip_cseq_t * cseq, int number);
#define sip_cseq_set_number(c,n) c->cseq_number=(apr_uint32_t)n

//void sip_cseq_set_method(struct sip_cseq_t * cseq, const char * method);
#define sip_cseq_set_method(c, m) c->cseq_method=apr_pstrdup(c->pool,m)

//unsigned long sip_cseq_get_number(const struct sip_cseq_t * cseq);
#define sip_cseq_get_number(c) (c->cseq_number)

//const char * sip_cseq_get_method(const struct sip_cseq_t * cseq);
#define sip_cseq_get_method(c) c->cseq_method

#endif
