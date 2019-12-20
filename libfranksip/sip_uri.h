#ifndef SIPVOICE_URI_H
#define SIPVOICE_URI_H

#include "sip_utils.h"
#include "sip_params.h"


//typedef struct sip_uri_t sip_uri_t;

struct sip_uri_t
{
	// 此处仅处理 SIP 或 SIPS 类型的URI
	//char *	scheme;		//URI类型 SIP
	// username:password@host:port   
	// lxf_programmer@163.com  也是正确的   
	//		username=lxf_programmer
	//		password=null
	//		host=163.com
	//		port=
	char *	username;	//用户名称
	//char *	password;	//密码
	char *	host;		//域名
	int		port;		//端口

//	unsigned char is_gateway;

	// 参数列表.
	// apr_hash_t * params;
	sip_paramlist_t * params;
	apr_pool_t * pool;
};

//可以被外部使用的函数.

struct sip_uri_t *  sip_uri_make(apr_pool_t * pool);
//void sip_uri_free(struct sip_uri_t * uri);

struct sip_uri_t *  sip_uri_parse(apr_pool_t * pool, char * buff);
struct sip_uri_t *  sip_uri_clone(apr_pool_t * pool, const struct sip_uri_t * src);
int  sip_uri_to_string(const struct sip_uri_t * uri, char * buff, int len);

// void sip_uri_set_username(struct sip_uri_t * uri, const char * username);
#define sip_uri_set_username(uri, usr) (uri)->username= usr?apr_pstrdup((uri)->pool, usr):0

//void sip_uri_set_password(struct sip_uri_t * uri, const char * password);
//#define sip_uri_set_password(uri, pwd) if(pwd) (uri)->password=apr_pstrdup((uri)->pool,pwd); else (uri)->password=0

//void sip_uri_set_domain(struct sip_uri_t * uri, const char * host, int port);
#define sip_uri_set_domain(uri, h,p) (uri)->host = apr_pstrdup((uri)->pool, h); (uri)->port = p

//#define sip_uri_set_gateway(uri, b) (uri)->is_gateway=b

//const char * sip_uri_get_username(struct sip_uri_t * uri);
#define sip_uri_get_username(uri) (uri)->username

//const char * sip_uri_get_password(struct sip_uri_t * uri);
//#define sip_uri_get_password(uri) (uri)->password

//const char * sip_uri_get_host(struct sip_uri_t * uri);
#define sip_uri_get_host(uri) (uri)->host

//int sip_uri_get_port(struct sip_uri_t * uri);
#define sip_uri_get_port(uri) (uri)->port

//void sip_uri_set_param(struct sip_uri_t * uri, const char * key, const char * value);
#define sip_uri_set_param(uri, key, value) \
	if (NULL == (uri)->params) (uri)->params = sip_generic_param_make((uri)->pool); \
	sip_generic_param_set((uri)->params, key, value)

//const char * sip_uri_get_param(struct sip_uri_t * uri, const char * key);
#define sip_uri_get_param(uri, key) (uri)->params?sip_generic_param_get((uri)->params,key):0


#endif
