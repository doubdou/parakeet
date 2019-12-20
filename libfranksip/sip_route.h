#ifndef SIPVOICE_ROUTE_T
#define SIPVOICE_ROUTE_T

#include "sip_utils.h"
#include "sip_uri.h"

struct sip_route_t
{
	apr_pool_t * pool;
	char * domain;	// IP:Port 或 域名.
	char * lr;

	struct sip_route_t * next;
};

struct sip_route_t * sip_route_make(apr_pool_t * pool);
struct sip_route_t * sip_route_parse(apr_pool_t * pool, char * buff);
struct sip_route_t * sip_route_clone(apr_pool_t * pool, struct sip_route_t * src);
int sip_route_tostring(const struct sip_route_t * route, char * buff, int len);


#endif

