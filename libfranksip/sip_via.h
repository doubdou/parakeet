#ifndef SIP_VIA_H
#define SIP_VIA_H

#include "sip_utils.h"
#include "sip_params.h"

struct sip_via_t
{
	apr_pool_t *	pool;
	char *			host;
	int				port;
	sip_paramlist_t * params;

	// 下一个
	struct sip_via_t * next;
};

struct sip_via_t *  sip_via_make(apr_pool_t * pool);

struct sip_via_t *  sip_via_parse(apr_pool_t * pool, char * buff);
struct sip_via_t *  sip_via_clone(apr_pool_t * pool, const struct sip_via_t * via);
int sip_via_to_string(const struct sip_via_t * via, char * buff, int len);

// 修改Host
#define sip_via_set_host(v,h) v->host=apr_pstrdup(v->pool,h)
#define sip_via_get_host(v) v->host

#define sip_via_set_port(v, p) v->port=p
#define sip_via_get_port(v) v->port

int sip_via_match(const struct sip_via_t * via1, const struct sip_via_t * via2);

//设置参数.
#define sip_via_set_param(via,k,v) sip_generic_param_set(via->params,k,v)

#define sip_via_set_hidden(via) sip_via_set_param(via, "hidden", "")
#define sip_via_set_maddr(via, value) sip_via_set_param(via, "maddr", value)
#define sip_via_set_received(via, value) sip_via_set_param(via, "received", value)
#define sip_via_set_branch(via, value) sip_via_set_param(via, "branch", value)
#define sip_via_set_rport(via,value) sip_via_set_param(via,"rport",value)

// 获取参数.
//const char * sip_via_get_param(const struct sip_via_t * via, const char * key);
#define sip_via_get_param(via,k) sip_generic_param_get(via->params,k)

#define sip_via_get_branch(via) sip_via_get_param(via, "branch")
#define sip_via_get_received(via) sip_via_get_param(via, "received")
#define sip_via_get_maddr(via) sip_via_get_param(via, "maddr")
#define sip_via_get_rport(via) sip_via_get_param(via, "rport")

#endif

