#ifndef SIP_PARAMETER_H
#define SIP_PARAMETER_H

#include "sip_utils.h"

// 参数需要有序的.

typedef struct sip_paramnode_t sip_paramnode_t;
struct sip_paramnode_t
{
	char * key;
	char * value;
	sip_paramnode_t * next;
};

typedef struct sip_paramlist_t sip_paramlist_t;
struct sip_paramlist_t
{
	apr_pool_t * pool;
	sip_paramnode_t * head;
	sip_paramnode_t * tail;
};

sip_paramlist_t * sip_generic_param_make(apr_pool_t * pool);
void sip_generic_param_set(sip_paramlist_t * params, const char * key, const char * value);
void sip_generic_param_add(sip_paramlist_t * params, const char * key, apr_size_t klen, const char * value, apr_size_t vlen);
const char * sip_generic_param_get(sip_paramlist_t * params, const char * key);
sip_paramlist_t *  sip_generic_param_clone(apr_pool_t * pool, const sip_paramlist_t * params);
sip_paramlist_t * sip_generic_param_parse(apr_pool_t * pool, const char * str);
int  sip_generic_param_to_string(const sip_paramlist_t * params, char * buff, int len);

#if 0
// 设置参数
void sip_generic_param_set(apr_pool_t *pool, apr_hash_t * params, const char * key, const char * value);
// 获取参数
const char * sip_generic_param_get(apr_hash_t * params, const char * key);

// 复制参数
apr_hash_t *  sip_generic_param_clone(apr_pool_t * pool, const apr_hash_t * params);

// 解析缓存, 保存为参数列表.
apr_hash_t * sip_generic_param_parse(apr_pool_t * pool, const char * str);

// 转换为字符串到buff中.
int  sip_generic_param_to_string(const apr_hash_t * params, char * buff, int len);
#endif


#endif

