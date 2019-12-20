#pragma once

#include "sip_utils.h"

struct sip_www_authenticate_t
{
	apr_pool_t * pool;
    //char * auth_type;		/**< Authentication Type (Basic or Digest */
    char * realm;		/**< realm (as a quoted-string) */
    char * domain;		/**< domain (optional) */
    char * nonce;		/**< nonce (optional)*/
    char * opaque;		/**< opaque (optional) */
    char * stale;		/**< stale (optional) */
    char * algorithm;		/**< algorythm (optional) */
    char * qop_options;		/**< qop option (optional)  */
    char * auth_param;		/**< other parameters (optional) */
};

struct sip_www_authenticate_t * sip_www_authenticate_make(apr_pool_t * pool);
struct sip_www_authenticate_t * sip_www_authenticate_parse(apr_pool_t * pool, char * buff);
struct sip_www_authenticate_t * sip_www_authenticate_clone(apr_pool_t * pool, const struct sip_www_authenticate_t * src);
int  sip_www_authenticate_to_string(const struct sip_www_authenticate_t * auth, char * buff, int size);
void sip_www_authenticat_set(struct sip_www_authenticate_t * auth, const char * nonce, const char * realm);



