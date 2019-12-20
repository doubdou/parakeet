#include "sip_cseq.h"


struct sip_cseq_t * sip_cseq_make(apr_pool_t * pool)
{
	struct sip_cseq_t * cseq = (struct sip_cseq_t *)apr_pcalloc(pool,sizeof(struct sip_cseq_t));
	assert(cseq);

	cseq->pool = pool;

	return cseq;
}


struct sip_cseq_t * sip_cseq_parse(apr_pool_t * pool, const char * buff)
{
	//格式:
	// CSeq: 1 INVITE
	struct sip_cseq_t * cseq;
	char * str;
	
	//while (*buff == ' ' || *buff == '\t')buff++;
	assert(*buff != ' ' && *buff != '\t');

	str = strchr(buff, ' ');
	if (NULL == str)return NULL;

	cseq = sip_cseq_make(pool);
	str++;

	cseq->cseq_number = (apr_uint32_t)apr_atoi64(buff);
	cseq->cseq_method = apr_pstrdup(pool, str);

	return cseq;
}


struct sip_cseq_t * sip_cseq_clone(apr_pool_t * pool, const struct sip_cseq_t * src)
{
	//复制CSeq.
	struct sip_cseq_t * tmp = sip_cseq_make(pool);

	assert(src->cseq_method);
	assert(src->cseq_number);

	tmp->cseq_method = apr_pstrdup(pool, src->cseq_method);
	tmp->cseq_number = src->cseq_number;

	return tmp;
}

int  sip_cseq_to_string(const struct sip_cseq_t * cseq, char * buff, int len)
{
	assert(cseq);
	assert(cseq->cseq_method);
	assert(cseq->cseq_number);

	return apr_snprintf(buff, (apr_size_t)len, "%u %s", cseq->cseq_number, cseq->cseq_method);
}

/****
void sip_cseq_set_number(struct sip_cseq_t * cseq, int number)
{
	assert(cseq);
	cseq->cseq_number = number;
}

void sip_cseq_set_method(struct sip_cseq_t * cseq, const char * method)
{
	assert(method);
	assert(cseq);
	assert(cseq->pool);

	cseq->cseq_method = apr_pstrdup(cseq->pool, method);
}

unsigned long sip_cseq_get_number(const struct sip_cseq_t * cseq)
{
	assert(cseq);
	return cseq->cseq_number;
}

const char * sip_cseq_get_method(const struct sip_cseq_t * cseq)
{
	assert(cseq);
	return cseq->cseq_method;
}
***/

