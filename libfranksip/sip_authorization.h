#ifndef SIPVOICE_AUTHORIZATION_H
#define SIPVOICE_AUTHORIZATION_H

#include "sip_utils.h"


struct sip_authorization_t
{
	apr_pool_t * pool;
	char * auth_type;		//  类型: Basic 或 Digest; Authentication Type (Basic or Digest)
	char * username;		//  登录用户名; login
	char * realm;			//	realm (as a quoted-string)
	char * nonce;			//	nonce
	char * uri;  			//	uri
	char * response;		//	response
	char * digest;			//	digest
	char * algorithm;		//	算法(可选); algorithm (optionnal)
	char * cnonce;			//	cnonce (optionnal)
	char * opaque;			//	opaque (optionnal)
	char * message_qop;		//	message_qop (optionnal)
	char * nonce_count;		//	nonce_count (optionnal)
	char * auth_param;		//	其他参数(可选); other parameters (optionnal)
};

struct sip_authorization_t *  sip_authorization_make(apr_pool_t * pool);

// 解析auth
struct sip_authorization_t *  sip_authorization_parse(apr_pool_t * pool, const char * buff);
// 复制auth
struct sip_authorization_t *  sip_authorization_clone(apr_pool_t * pool, const struct sip_authorization_t * src);
// 转换auth为字符串
int  sip_authorization_to_string(const struct sip_authorization_t * auth, char * buff, int size);

int  sip_authorization_set_param(struct sip_authorization_t * auth,
					const char * auth_type,
					const char * username,
					const char * domain,
					const char * nonce,
					const char * alg,
					const char * uri);
int  sip_authorization_set_param2(struct sip_authorization_t * auth,
					const char * qop,
					const char * nc,
					const char * opaque,
					const char * cnonce);
int  sip_authorization_set_response(struct sip_authorization_t * auth, const char * response);


void sip_auth_make_response(const struct sip_authorization_t * auth, const char * method, const char * password, char * response);
int	 sip_authorization_verify(const struct sip_authorization_t * auth, const char * method, const char * password);

void sip_auth_convert_callid2nonce(const char * callid, char nonce[36]);

#endif

