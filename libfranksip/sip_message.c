#include "sip_message.h"
#include "sip_utils.h"

#include "sip_authorization.h"
#include "sip_www_authenticate.h"
#include "sip_cseq.h"
#include "sip_uri.h"
#include "sip_via.h"
#include "sip_contact.h"
#include "sip_content_type.h"
#include "sip_session_expires.h"
#include "sip_supported.h"
#include "sip_route.h"

typedef int(*sip_parser_t)(sip_message_t *, char * str);

struct sip_message_t
{
	apr_pool_t *	pool;

	//////////////////////////////////////////////////////////////////////
	// First Line
	// Request.
	struct sip_uri_t * request_uri;
	char * request_method;

	// Response.
	int response_status_code;
	char * response_reason_phrase;	///< 状态说明

	//////////////////////////////////////////////////////////////////////
	// Headers

	char *	call_id;			///< Call-ID 必选
	struct sip_via_t * vias;	///< Via 必选
	struct sip_contact_t * from;	///< From 必选
	struct sip_contact_t * to;		///< To 必选
	struct sip_cseq_t * cseq;		///< CSeq 必选

	//////////////////////////////////////////////////////////////////////
	// 所有Request 和 200, 3xx 必选的.
	struct sip_contact_t * contact;	///< Contact 联系地址必选
	sip_content_type_t  * content_type;
	char *  body;

	// 所有Request 必选的.
	int		maxforwards;

	//////////////////////////////////////////////////////////////////////
	// 注册鉴权消息中必选.
	struct sip_authorization_t * auth;
	struct sip_www_authenticate_t * www;
	char *	expires;		// Expires字段值.

	//////////////////////////////////////////////////////////////////////
	// 呼叫鉴权消息中必选
	struct sip_www_authenticate_t * proxy_www;
	struct sip_authorization_t * proxy_auth;

	//////////////////////////////////////////////////////////////////////
	// 路由处理 (可选)
	struct sip_route_t * record_routes;	///< 在INVITE中附加. 在Response保留
	struct sip_route_t * routes;			///< 在BYE,CANCEL中附加

	//////////////////////////////////////////////////////////////////////
	// 会话超时判断
	struct sip_session_expires_t * session_expires;
	struct sip_supported_t * supported;
	int		min_se;

	//////////////////////////////////////////////////////////////////////
	// 用户代理信息.
	char *	user_agent;

	//////////////////////////////////////////////////////////////////////
	// 可支持的方法.
	char *  allows;

	//////////////////////////////////////////////////////////////////////
	// 未能解析的Headers
	apr_hash_t * headers;
};


static const char * sip_get_status_string(int status_code);

//以下是须存在的头域. (RFC3261)
//头域1.1:To
static int sip_message_parse_to(sip_message_t * sip, char * hvalue);
//头域1.2:From
static int sip_message_parse_from(sip_message_t * sip, char * hvalue);
//头域1.3:Call-ID
static int sip_message_parse_call_id(sip_message_t * sip, char * hvalue);
//头域1.4:CSeq
static int sip_message_parse_cseq(sip_message_t * sip, char * hvalue);
//头域1.5:Contact
static int sip_message_parse_contact(sip_message_t * sip, char * hvalue);
//头域1.6:Max-Forwards
static int sip_message_parse_max_forward(sip_message_t * sip, char * hvalue);
//头域1.7:Via
static int sip_message_parse_via(sip_message_t * sip, char * hvalue);

static int  sip_message_parse_session_expires(sip_message_t * sip, char * hvalue);
static int  sip_message_parse_supported(sip_message_t * sip, char * hvalue);
static int  sip_message_parse_min_session_expires(sip_message_t * sip, char * hvalue);

//头域2.3:Content-Type
static int sip_message_parse_content_type(sip_message_t * sip, char * hvalue);
//头域2.4
static int sip_message_parse_allow(sip_message_t * sip, char * hvalue);
static int sip_message_parse_user_agent(sip_message_t * sip, char * hvalue);

//以下是每个SIP基本都有的头域:
//头域3.1:Content-Length
static int sip_message_parse_content_length(sip_message_t * sip, char * hvalue);
//头域3.2:Expires
static int sip_message_parse_expires(sip_message_t * sip, char * hvalue);

//以下是注册时需要的头域:
static int sip_message_parse_authorization(sip_message_t * sip, char * hvalue);
static int sip_message_parse_www_authenticate(sip_message_t * sip, char * hvalue);

static int  sip_message_parse_proxy_authenticate(sip_message_t * sip, char * hvalue);
static int  sip_message_parse_proxy_authorization(sip_message_t * sip, char * hvalue);

static int  sip_message_parse_record_route(sip_message_t * sip, char * hvalue);
static int  sip_message_parse_route(sip_message_t * sip, char * hvalue);


static struct
{
	apr_pool_t * pool;
	apr_hash_t * parser;
	apr_uint32_t next_tag;
	apr_uint32_t next_seq;
}globals;

FRANKSIP_DECLARE void sip_initialize(void)
{
	//对于预定义的Header的处理有多种方式
	//如下两种效率较高, 
	// (1) 对预定义的Headers升序排序, 检索时使用二分法
	// (2) 建立Hash映射表
	//经过比较二分法排序比Hash索引速度还快些
	// 另外还有一种方法, 效率也非常高, 与二分法差不多, 但是代码不太好维护.
	// 即: 首先比较hname的第一个字符, 相同的话再比较全部字符.
	// 下面代码是使用希尔排序的

	memset(&globals, 0, sizeof(globals));
	apr_pool_create(&globals.pool, 0);
	apr_atomic_init(globals.pool);

	globals.next_seq = 1;
	globals.next_tag = (apr_uint32_t)time(NULL);

	globals.parser = apr_hash_make(globals.pool);

	/****

	{ "Accept",		    6,  NULL },   // PJSIP_H_ACCEPT,
	{ "Accept-Encoding",    15, NULL },   // PJSIP_H_ACCEPT_ENCODING,
	{ "Accept-Language",    15, NULL },   // PJSIP_H_ACCEPT_LANGUAGE,
	{ "Alert-Info",	    10, NULL },   // PJSIP_H_ALERT_INFO,
	{ "Allow",		    5,  NULL },   // PJSIP_H_ALLOW,
	{ "Authentication-Info",19, NULL },   // PJSIP_H_AUTHENTICATION_INFO,
	{ "Authorization",	    13, NULL },   // PJSIP_H_AUTHORIZATION,
	{ "Call-ID",	    7,  "i" },    // PJSIP_H_CALL_ID,
	{ "Call-Info",	    9,  NULL },   // PJSIP_H_CALL_INFO,
	{ "Contact",	    7,  "m" },    // PJSIP_H_CONTACT,
	{ "Content-Disposition",19, NULL },   // PJSIP_H_CONTENT_DISPOSITION,
	{ "Content-Encoding",   16, "e" },    // PJSIP_H_CONTENT_ENCODING,
	{ "Content-Language",   16, NULL },   // PJSIP_H_CONTENT_LANGUAGE,
	{ "Content-Length",	    14, "l" },    // PJSIP_H_CONTENT_LENGTH,
	{ "Content-Type",	    12, "c" },    // PJSIP_H_CONTENT_TYPE,
	{ "CSeq",		     4, NULL },   // PJSIP_H_CSEQ,
	{ "Date",		     4, NULL },   // PJSIP_H_DATE,
	{ "Error-Info",	    10, NULL },   // PJSIP_H_ERROR_INFO,
	{ "Expires",	     7, NULL },   // PJSIP_H_EXPIRES,
	{ "From",		     4, "f" },    // PJSIP_H_FROM,
	{ "In-Reply-To",	    11, NULL },   // PJSIP_H_IN_REPLY_TO,
	{ "Max-Forwards",	    12, NULL },   // PJSIP_H_MAX_FORWARDS,
	{ "MIME-Version",	    12, NULL },   // PJSIP_H_MIME_VERSION,
	{ "Min-Expires",	    11, NULL },   // PJSIP_H_MIN_EXPIRES,
	{ "Organization",	    12, NULL },   // PJSIP_H_ORGANIZATION,
	{ "Priority",	     8, NULL },   // PJSIP_H_PRIORITY,
	{ "Proxy-Authenticate", 18, NULL },   // PJSIP_H_PROXY_AUTHENTICATE,
	{ "Proxy-Authorization",19, NULL },   // PJSIP_H_PROXY_AUTHORIZATION,
	{ "Proxy-Require",	    13, NULL },   // PJSIP_H_PROXY_REQUIRE,
	{ "Record-Route",	    12, NULL },   // PJSIP_H_RECORD_ROUTE,
	{ "Reply-To",	     8, NULL },   // PJSIP_H_REPLY_TO,
	{ "Require",	     7, NULL },   // PJSIP_H_REQUIRE,
	{ "Retry-After",	    11, NULL },   // PJSIP_H_RETRY_AFTER,
	{ "Route",		     5, NULL },   // PJSIP_H_ROUTE,
	{ "Server",		     6, NULL },   // PJSIP_H_SERVER,
	{ "Subject",	     7, "s" },    // PJSIP_H_SUBJECT,
	{ "Supported",	     9, "k" },    // PJSIP_H_SUPPORTED,
	{ "Timestamp",	     9, NULL },   // PJSIP_H_TIMESTAMP,
	{ "To",		     2, "t" },    // PJSIP_H_TO,
	{ "Unsupported",	    11, NULL },   // PJSIP_H_UNSUPPORTED,
	{ "User-Agent",	    10, NULL },   // PJSIP_H_USER_AGENT,
	{ "Via",		     3, "v" },    // PJSIP_H_VIA,
	{ "Warning",	     7, NULL },   // PJSIP_H_WARNING,
	{ "WWW-Authenticate",   16, NULL },   // PJSIP_H_WWW_AUTHENTICATE,

	****/

#define SET_HEAD_FUNCTION(NAME,FUN) apr_hash_set(globals.parser, NAME, APR_HASH_KEY_STRING, &FUN)


	SET_HEAD_FUNCTION(HNAME_TO, sip_message_parse_to);
	SET_HEAD_FUNCTION("t", sip_message_parse_to);
	SET_HEAD_FUNCTION(HNAME_FROM, sip_message_parse_from);
	SET_HEAD_FUNCTION("f", sip_message_parse_from);
	SET_HEAD_FUNCTION(HNAME_CALL_ID, sip_message_parse_call_id);
	SET_HEAD_FUNCTION("i", sip_message_parse_call_id);
	SET_HEAD_FUNCTION(HNAME_CONTACT, sip_message_parse_contact);
	SET_HEAD_FUNCTION("m", sip_message_parse_contact);
	SET_HEAD_FUNCTION(HNAME_CONTENT_TYPE, sip_message_parse_content_type);
	SET_HEAD_FUNCTION("c", sip_message_parse_content_type);
	SET_HEAD_FUNCTION(HNAME_CONTENT_LENGTH, sip_message_parse_content_length);
	SET_HEAD_FUNCTION("l", sip_message_parse_content_length);
	SET_HEAD_FUNCTION(HNAME_ALLOW, sip_message_parse_allow);
	SET_HEAD_FUNCTION(HNAME_CSEQ, sip_message_parse_cseq);
	SET_HEAD_FUNCTION(HNAME_EXPIRES, sip_message_parse_expires);
	SET_HEAD_FUNCTION(HNAME_MAX_FORWARDS, sip_message_parse_max_forward);
	SET_HEAD_FUNCTION(HNAME_USER_AGENT, sip_message_parse_user_agent);
	SET_HEAD_FUNCTION(HNAME_VIA, sip_message_parse_via);
	SET_HEAD_FUNCTION("v", sip_message_parse_via);
	SET_HEAD_FUNCTION(HNAME_SUPPORTED, sip_message_parse_supported);
	SET_HEAD_FUNCTION(HNAME_SESSION_EXPIRES, sip_message_parse_session_expires);
	SET_HEAD_FUNCTION(HNAME_MIN_SESSION_EXPIRES, sip_message_parse_min_session_expires);
	SET_HEAD_FUNCTION(HNAME_AUTHORIZATION, sip_message_parse_authorization);
	SET_HEAD_FUNCTION(HNAME_WWW_AUTHENTICATE, sip_message_parse_www_authenticate);
	SET_HEAD_FUNCTION(HNAME_PROXY_AUTHENTICATE, sip_message_parse_proxy_authenticate);
	SET_HEAD_FUNCTION(HNAME_PROXY_AUTHORIZATION, sip_message_parse_proxy_authorization);

	SET_HEAD_FUNCTION(HNAME_RECORD_ROUTE, sip_message_parse_record_route);
	SET_HEAD_FUNCTION(HNAME_ROUTE, sip_message_parse_route);
}

FRANKSIP_DECLARE const char * sip_rand_string(char * buf, int size)
{
	static char content[] = "0123456789abcdefghijklmnopqrstuvwxyz";
#define CONTENT_LENGTH	(sizeof(content)-1)

	char * str = buf;
	char * end = buf + size - 1;
	apr_uint32_t seq = apr_atomic_inc32(&globals.next_seq);
	apr_uint32_t n = seq;

	// 序号
	while (n)
	{
		*str++ = content[n % CONTENT_LENGTH];
		n /= CONTENT_LENGTH;
	}

	// 时间
	if (str < end)
	{
		n = (unsigned int)time(NULL) ^ seq;
		do
		{
			*str++ = content[n % CONTENT_LENGTH];
			n /= CONTENT_LENGTH;
		} while (str < end && n>0);
	}

	// CPU时间.
	if (str < end)
	{
		n = (unsigned int)clock();
		do
		{
			*str++ = content[n % CONTENT_LENGTH];
			n /= CONTENT_LENGTH;
		} while (str < end && n>0);
	}

	// 随机数
	while (str < end)
	{
		n = (unsigned int)rand();
		do
		{
			*str++ = content[n % CONTENT_LENGTH];
			n /= CONTENT_LENGTH;
		} while (str < end && n>0);
	}
	*str = 0;

	return buf;
}

FRANKSIP_DECLARE const char * sip_rand_tag(char  buf[16])
{
	sprintf(buf, "%8x", apr_atomic_inc32(&globals.next_tag));
	return buf;
}


FRANKSIP_DECLARE sip_message_t *  sip_message_create(void)
{
	sip_message_t *  msg;
	apr_pool_t * pool;

	apr_pool_create(&pool, 0);
	assert(pool);
	msg = (sip_message_t *)apr_pcalloc(pool, sizeof(sip_message_t));
	assert(msg);
	msg->pool = pool;

	return msg;
}

FRANKSIP_DECLARE void sip_message_free(sip_message_t * sip)
{
	if (NULL == sip)return;
	assert(sip);
	assert(sip->pool);
	apr_pool_destroy(sip->pool);
}

// 不完整的复制SIP消息.
FRANKSIP_DECLARE sip_message_t *  sip_message_clone_simple(const sip_message_t * src)
{
	// 复制 SIP,
	// 注意: 本函数不复制如下信息:
	//  1.Contact
	//  2.SDP
	//  3.Headers.
	//  4.Max-Forward
	//  5.Expires.
	//  6.Content-Type
	//  7.Allow

	sip_message_t * msg;

	assert(src);
	assert(src->call_id);
	assert(src->from);
	assert(src->to);
	assert(src->cseq);
	assert(src->vias);

	if (NULL == src->call_id ||
		NULL == src->from ||
		NULL == src->to ||
		NULL == src->cseq ||
		NULL == src->vias)
		return NULL;

	msg = sip_message_create();
	assert(msg);
	assert(msg != src);

	// Request.
	if ( src->request_method ) 
	{
		msg->request_method = apr_pstrdup(msg->pool, src->request_method);
		msg->request_uri = sip_uri_clone(msg->pool, src->request_uri);
	}
	else
	{
		msg->response_status_code = src->response_status_code;
		if ( src->response_reason_phrase ) 
			msg->response_reason_phrase = apr_pstrdup(msg->pool,src->response_reason_phrase);
	}
	if ( ( msg->request_uri == NULL || msg->request_method == NULL ) &&
		(msg->response_status_code == 0) )
	{
		sip_message_free(msg);
		return NULL;
	}
	
	msg->call_id = apr_pstrdup(msg->pool, src->call_id);
	msg->cseq = sip_cseq_clone(msg->pool, src->cseq);
	msg->from = sip_contact_clone(msg->pool, src->from);
	msg->to = sip_contact_clone(msg->pool, src->to);

	if (src->vias)
	{
		struct sip_via_t * tail = 0;
		struct sip_via_t * tmp = 0;

		struct sip_via_t * via = src->vias;
		while (via)
		{
			tmp = sip_via_clone(msg->pool, via);
			assert(tmp);
			if (tmp)
			{
				tmp->next = 0;
				if (tail)
				{
					tail->next = tmp;
				}
				else
				{
					msg->vias = tmp;
				}
				tail = tmp;
			}
			via = via->next;
		}
	}

	if (src->record_routes)
	{
		struct sip_route_t * tail = 0;
		struct sip_route_t * tmp = 0;
		struct sip_route_t * route = src->record_routes;
		while (route)
		{
			tmp = sip_route_clone(msg->pool, route);
			if (tmp)
			{
				if (tail)
				{
					tail->next = tmp;
				}
				else
				{
					msg->record_routes = tmp;
				}
				tail = tmp;
			}
			route = route->next;
		}
	}

	if (src->routes)
	{
		struct sip_route_t * tail = 0;
		struct sip_route_t * tmp = 0;
		struct sip_route_t * route = src->routes;
		while (route)
		{
			tmp = sip_route_clone(msg->pool, route);
			if (tmp)
			{
				if (tail)
				{
					tail->next = tmp;
				}
				else
				{
					msg->routes = tmp;
				}
				tail = tmp;
			}
			route = route->next;
		}
	}

	return msg;
}

FRANKSIP_DECLARE sip_message_t* sip_message_create_response(const sip_message_t* sip, int status_code, const char* phrase)
{
	// 准备回应消息.
	sip_message_t* resp = sip_message_clone_simple(sip);
	if (resp)
	{
		resp->response_status_code = status_code;
		resp->request_method = NULL;

		if (phrase)
		{
			resp->response_reason_phrase = apr_pstrdup(resp->pool, phrase);
		}
	}

	return resp;
}


// 解析SIP消息.
FRANKSIP_DECLARE sip_message_t *  sip_message_parse(char * buff, int length)
{
	// 处理第一行.
	char * next_header = NULL;
	char * str;

	sip_message_t * msg = sip_message_create();
	assert(msg);
	if (NULL == msg) return NULL;

	// 解析首行.

	if (strncmp(buff, "SIP/2.0 ", 8) == 0)
	{
		// 这是一个Response.
		buff += 8;
		// status code 必定是3位的.
		if (buff[3] != ' ') goto err;
	//	buff[3] = 0;
		msg->response_status_code = atoi(buff);
		buff += 4;
		str = strchr(buff, '\r');
		if (NULL == str) goto err;
		*str = 0;
		msg->response_reason_phrase = apr_pstrdup(msg->pool, buff);

		str++;
		if ('\n' == *str)str++;
		next_header = str;
	}
	else
	{
		// 这是一个Request.
		str = strchr(buff, ' ');
		if (NULL == str) goto err;
		*str = 0;
		str++;
		msg->request_method = apr_pstrdup(msg->pool, buff);
		buff = str;
		str = strchr(buff, ' ');
		if (NULL == str)goto err;
		*str = 0;
		msg->request_uri = sip_uri_parse(msg->pool, buff);
		if (NULL == msg->request_uri) goto err;
		str++;
		str = strchr(str, '\r');
		if (NULL == str)goto err;
		str++;
		if ('\n' != *str) goto err;
		str++;
		next_header = str;
	}

	// 解析headers
	while ('\0' != *next_header && '\r' != *next_header)
	{
		char * name = next_header;
		char * value;
		sip_parser_t parser;

		str = strchr(name, ':');
		if (NULL == str) goto err;
		*str = 0;
		str++;
		value = str;
		if (' ' == *value)value++;
		str = strchr(value, '\r');
		if (NULL == str) goto err;
		*str = 0;
		str++;
		if ('\n' != *str)goto err;
		str++;
		next_header = str;

		parser = (sip_parser_t)apr_hash_get(globals.parser, name, APR_HASH_KEY_STRING);
		if (parser)
		{
			if (0 != parser(msg, value)) goto err;
		}
		else
		{
			if (NULL == msg->headers)
			{
				msg->headers = apr_hash_make(msg->pool);
			}
			apr_hash_set(msg->headers, apr_pstrdup(msg->pool, name), APR_HASH_KEY_STRING, apr_pstrdup(msg->pool, value));
		}
	}

	 //如果有body...
	if ( '\r' == next_header[0] && '\n' == next_header[1] )
	{
		msg->body = apr_pstrdup(msg->pool, next_header + 2);
	}
	return msg;

err:
	sip_message_free(msg);
	return NULL;
}

// 检查SIP消息是否有效.
// 返回0: 有效, 返回-1:无效
FRANKSIP_DECLARE int  sip_message_verify(const sip_message_t * sip)
{
	//验证SIP有效性.
	if (NULL == sip->call_id ||
		NULL == sip->cseq ||
		NULL == sip->from ||
		NULL == sip->to ||
		NULL == sip->vias)
		return -1;

	if ( (0 == sip->request_uri || 0 == sip->request_method) &&
		0 == sip->response_status_code )
		return -1;

	// 主叫/被叫必须存在.
	if (NULL == sip->from->uri  ||	NULL == sip->to->uri )
		return -1;


	return 0;
}

FRANKSIP_DECLARE int  sip_message_to_string(const sip_message_t * sip, char * buff, int size)
{
	int len;

	assert( NULL != sip );

	if ( sip->response_status_code > 0 )
	{
		assert( NULL == sip->request_method );
		len = apr_snprintf(buff, (apr_size_t)size, "SIP/2.0 %i %s\r\n",
			sip->response_status_code,
			(sip->response_reason_phrase == NULL) ? sip_get_status_string(sip->response_status_code) : sip->response_reason_phrase);
	}
	else
	{
		assert( NULL != sip->request_method );
		assert( NULL == sip->response_reason_phrase );
		assert(NULL != sip->request_uri);

		len = apr_snprintf(buff, (apr_size_t)size, "%s ", sip->request_method);
		len += sip_uri_to_string(sip->request_uri, buff + len, (apr_size_t)(size - len));
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), " SIP/2.0\r\n");
	}

	// Vias.
	if (sip->vias)
	{
		const struct sip_via_t * via = sip->vias;
		while (via)
		{
			len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_VIA ": ");
			len += sip_via_to_string(via, buff + len, size - len);
			buff[len++] = '\r';
			buff[len++] = '\n';

			via = via->next;
		}
	}

	// From.
	assert(sip->from);
	len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_FROM ": ");
	len += sip_contact_to_string(sip->from, buff + len, size - len);
	buff[len++] = '\r';
	buff[len++] = '\n';

	// To.
	assert( sip->to );
	len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_TO ": ");
	len += sip_contact_to_string(sip->to, buff + len, size - len);
	buff[len++] = '\r';
	buff[len++] = '\n';

	// Call-ID.
	assert(sip->call_id);
	len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_CALL_ID ": %s\r\n", sip->call_id);

	// CSeq.
	assert(sip->cseq);
	len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_CSEQ ": ");
	len += sip_cseq_to_string(sip->cseq, buff + len, size - len);
	buff[len++] = '\r';
	buff[len++] = '\n';

	// Contact
	if ( sip->contact )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_CONTACT ": ");
		len += sip_contact_to_string(sip->contact, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}

	// Allows.
	// 如果Allows存在内容.
	if (sip->allows)
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_ALLOW ": %s\r\n", sip->allows);
	}

	if ( sip->user_agent )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_USER_AGENT ": %s\r\n", sip->user_agent);
	}

	if ( sip->maxforwards > 0  )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_MAX_FORWARDS ": %d\r\n", sip->maxforwards);
	}

	if ( sip->expires  )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_EXPIRES ": %s\r\n", sip->expires);
	}

	// Session-Expires.
	if (sip->session_expires)
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_SESSION_EXPIRES ": ");
		len += sip_session_expires_to_string(sip->session_expires, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}

	if (sip->min_se > 0)
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_MIN_SESSION_EXPIRES ": %d\r\n", sip->min_se);
	}

	if (sip->supported)
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_SUPPORTED ": ");
		len += sip_supported_to_string(sip->supported, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}
	
	// Authorization
	if ( sip->auth ) 
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_AUTHORIZATION ": ");
		len += sip_authorization_to_string(sip->auth, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}

	if ( sip->www )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_WWW_AUTHENTICATE ": ");
		len += sip_www_authenticate_to_string(sip->www, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}

	// Proxy-Authorization.
	if ( sip->proxy_www )
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_PROXY_AUTHENTICATE ": ");
		len += sip_www_authenticate_to_string(sip->proxy_www, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}
	if (sip->proxy_auth)
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_PROXY_AUTHORIZATION ": ");
		len += sip_authorization_to_string(sip->proxy_auth, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}

	if (sip->record_routes)
	{
		const struct sip_route_t * route = sip->record_routes;
		while (route)
		{
			len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_RECORD_ROUTE ": ");
			len += sip_route_tostring(route, buff + len, size - len);
			buff[len++] = '\r';
			buff[len++] = '\n';

			route = route->next;
		}
	}
	
	if (sip->routes)
	{
		const struct sip_route_t * route = sip->routes;
		while (route)
		{
			len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_ROUTE ": ");
			len += sip_route_tostring(route, buff + len, size - len);
			buff[len++] = '\r';
			buff[len++] = '\n';

			route = route->next;
		}
	}

	// Headers.
	if (sip->headers)
	{
		apr_hash_index_t *hi;
		const char * key, *val;
		for (hi = apr_hash_first(0, sip->headers); hi; hi = apr_hash_next(hi))
		{
			key = apr_hash_this_key(hi);
			val = apr_hash_this_val(hi);
			//apr_hash_this(hi, (void**)&key, 0, (void**)&val);
			len += apr_snprintf(buff + len, (apr_size_t)(size - len), "%s: %s\r\n", key, val);
		}
	}

	if (sip->content_type)
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_CONTENT_TYPE ": ");
		len += sip_content_type_to_string(sip->content_type, buff + len, size - len);
		buff[len++] = '\r';
		buff[len++] = '\n';
	}

	// body.
	if ( sip->body )
	{
		// 请注意: sip->m_body_text 是否是0结尾的字符串.
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_CONTENT_LENGTH  ": %u\r\n\r\n%s",
			(unsigned int)strlen(sip->body), sip->body);
	}
	else
	{
		len += apr_snprintf(buff + len, (apr_size_t)(size - len), HNAME_CONTENT_LENGTH ": 0\r\n\r\n");
	}

	len++;
	return len;
}

FRANKSIP_DECLARE void sip_message_set_method(sip_message_t * sip, const char * method)
{
	assert( sip );
	assert( method );

	sip->request_method = apr_pstrdup(sip->pool, method);
	sip->response_status_code = 0;
	sip->response_reason_phrase = 0;
}

FRANKSIP_DECLARE const char * sip_message_get_method(const sip_message_t * sip)
{
	return sip->request_method;
}

FRANKSIP_DECLARE void sip_message_set_status_code(sip_message_t * sip, int status_code, const char * phrase)
{
	assert( sip );
	sip->request_method = NULL;
	sip->response_status_code = status_code;
	if (phrase)
	{
		sip->response_reason_phrase = apr_pstrdup(sip->pool, phrase);
	}
	else
	{
		sip->response_reason_phrase = NULL;
	}
}

FRANKSIP_DECLARE int sip_message_get_status_code(const sip_message_t * sip)
{
	return sip->response_status_code;
}

FRANKSIP_DECLARE const char * sip_message_get_phrase(const sip_message_t * sip)
{
	return sip->response_reason_phrase;
}

FRANKSIP_DECLARE void sip_message_set_request_uri(sip_message_t * sip, const char * username, const char * host, int port)
{
	assert(sip);
	assert(host);
	assert(port > 0);

	if (NULL == sip->request_uri)
	{
		sip->request_uri = sip_uri_make(sip->pool);
	}

	sip_uri_set_username(sip->request_uri, username);
	sip_uri_set_domain(sip->request_uri, host, port);
}

FRANKSIP_DECLARE void sip_message_set_request(sip_message_t * sip, const sip_contact_t * contact)
{
	assert(sip);
	assert(contact);

	sip->request_uri = sip_uri_clone(sip->pool, contact->uri);
}

FRANKSIP_DECLARE const char * sip_message_get_request_username(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->request_uri);
	if (NULL == sip->request_uri)return NULL;
	return sip_uri_get_username(sip->request_uri);
}

FRANKSIP_DECLARE const char * sip_message_get_request_host(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->request_uri);
	if (NULL == sip->request_uri)return NULL;
	return sip_uri_get_host(sip->request_uri);
}

FRANKSIP_DECLARE int sip_message_get_request_port(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->request_uri);
	if (NULL == sip->request_uri)return 0;
	return sip_uri_get_port(sip->request_uri);
}

FRANKSIP_DECLARE void sip_message_set_user_agent(sip_message_t * sip, const char * user_agent)
{
	if (user_agent && *user_agent)
	{
		sip->user_agent = apr_pstrdup(sip->pool, user_agent);
	}
	else
	{
		sip->user_agent = 0;
	}
}

FRANKSIP_DECLARE const char * sip_message_get_user_agent(const sip_message_t * sip)
{
	return sip->user_agent;
}

FRANKSIP_DECLARE void sip_message_set_expires( sip_message_t * sip, int expires )
{
	if ( expires < 0 )
	{
		sip->expires = NULL;
		sip_contact_set_expires(sip->contact, NULL);
	}
	else
	{
		if (NULL == sip->contact)
		{
			sip->expires = apr_itoa(sip->pool, expires);
		}
		else
		{
			const char * val = sip_contact_get_expires(sip->contact);
			if (val)
			{
				sip_contact_set_expires(sip->contact, apr_itoa(sip->pool, expires));
			}
			else
			{
				sip->expires = apr_itoa(sip->pool, expires);
			}
		}

	}
}

FRANKSIP_DECLARE int  sip_message_get_expires( sip_message_t * sip )
{
//	struct sip_contact_t * contact;
	const char * value;
	if (sip->expires) return (int)apr_atoi64(sip->expires);
	if (sip->contact)
	{
		value = sip_contact_get_expires(sip->contact);
		if (value)
			return (int)apr_atoi64(value);
	}
	return -1;
}

FRANKSIP_DECLARE void sip_message_set_content_type(sip_message_t * sip, const char * type)
{
	if (NULL == sip->content_type)
	{
		sip->content_type = sip_content_type_make(sip->pool);
	}
	sip_content_type_set_type(sip->content_type, type);
}

FRANKSIP_DECLARE int  sip_message_content_type_compare(const sip_message_t * sip, const char * type)
{
	if (NULL == sip->content_type)return -1;
	return sip_content_type_compare(sip->content_type, type);
}

FRANKSIP_DECLARE const char * sip_message_get_content_type(const sip_message_t * sip)
{
	if (NULL == sip->content_type)return NULL;
	return sip_content_type_get_type(sip->content_type);
}

FRANKSIP_DECLARE void sip_message_fix_top_via(sip_message_t * sip, const char * host, int port)
{
	// 第一个Via.
	char buf[16];
	if (NULL == sip->vias)return;

	sprintf(buf, "%d", port);
	sip_via_set_rport(sip->vias, buf);
	sip_via_set_received(sip->vias, host);
}



FRANKSIP_DECLARE int sip_message_insert_top_via(sip_message_t * sip, const char * host, int port, int new_branch)
{
	// 新增一个Via.

	struct sip_via_t * via;
	char buf[128];

	via = sip_via_make(sip->pool);
	sip_via_set_host(via, host);
	sip_via_set_port(via, port);

	strcpy(buf, SIP_BRANCH_PREFIX);
	if (new_branch)
	{
		sip_rand_string(buf + sizeof(SIP_BRANCH_PREFIX) - 1, 36);
	}
	else
	{
		const char * str, *end;
		char * ptr;
		if (NULL == sip->vias)return -1;
		str = sip_via_get_branch(sip->vias);
		str += (sizeof(SIP_BRANCH_PREFIX) - 1);
		end = str + strlen(str) - 1;
		ptr = buf + (sizeof(SIP_BRANCH_PREFIX) - 1);

		while (end >= str)
		{
			*ptr++ = *end--;
		}
		*ptr = 0;
	}
	sip_via_set_branch(via, buf);

	via->next = sip->vias;
	sip->vias = via;

	return 0;
}

FRANKSIP_DECLARE void sip_message_remove_top_via(sip_message_t * sip)
{
	assert(sip->vias);
	if (sip->vias)
	{
		sip->vias = sip->vias->next;
	}
}

FRANKSIP_DECLARE void sip_message_set_via_branch(sip_message_t * sip, const char * branch)
{
	if (sip->vias)
	{
		char buf[128];
		apr_snprintf(buf, sizeof(buf), SIP_BRANCH_PREFIX "%s", branch);

		sip_via_set_branch(sip->vias, buf);
	}
}


FRANKSIP_DECLARE const char* sip_message_get_topvia_branch(const sip_message_t* sip)
{
	if (NULL == sip->vias)
		return NULL;
	return sip_via_get_branch(sip->vias);
}

FRANKSIP_DECLARE void sip_message_set_call_id(sip_message_t * sip, const char * callid)
{
	assert(sip);
	assert(callid);
	sip->call_id = apr_pstrdup(sip->pool, callid);
}

FRANKSIP_DECLARE const char * sip_message_get_call_id(const sip_message_t * sip)
{
	return sip->call_id;
}


// from

FRANKSIP_DECLARE void sip_message_set_from_tag(sip_message_t * sip, const char * tag)
{
	assert(sip);
	assert(sip->from);
	if (tag)
	{
		if (NULL == sip->from)
		{
			sip->from = sip_contact_make(sip->pool);
		}
		sip_contact_set_tag(sip->from, tag);
	}
	else
	{
		if (sip->from) sip_contact_set_tag(sip->from, 0);
	}
}

FRANKSIP_DECLARE const char * sip_message_get_from_tag(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->from);
	return sip_contact_get_tag(sip->from);
}

FRANKSIP_DECLARE int sip_message_set_from_param(sip_message_t * sip, 
	const char * displayname,
	const char * username, const char * host,
	const char * tag)
{
	assert( sip );
	assert( host );
	assert(username);

	if (NULL == sip->from)
	{
		sip->from = sip_contact_make(sip->pool);
	}

	if (NULL != displayname)
	{
		sip_contact_set_displayname(sip->from, displayname);
		//if (displayname)  sip->from->displayname = apr_pstrdup(sip->from->pool, displayname); else sip->from->displayname = 0;
	}
	sip_contact_set_username(sip->from, username);
	sip_contact_set_domain(sip->from, host, 0);
	if (tag)
	{
		sip_message_set_from_tag(sip, tag);
	}
	return 0;
}


//FRANKSIP_DECLARE int  sip_message_set_from(sip_message_t * sip, sip_from_t * from)
//{
//	sip->from = from;
//	return 0;
//}

//FRANKSIP_DECLARE sip_from_t * sip_message_get_from(const sip_message_t * sip)
//{
//	return sip->from;
//}

FRANKSIP_DECLARE void sip_message_set_from_username(sip_message_t * sip, const char *username)
{
	assert(sip);
	assert(sip->from);
	if (NULL == sip->from)
	{
		sip->from = sip_contact_make(sip->pool);
	}
	sip_contact_set_username(sip->from, username);
}

FRANKSIP_DECLARE const char * sip_message_get_from_username(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->from);
	if (NULL == sip->from)return NULL;
	return sip_contact_get_username(sip->from);
}

FRANKSIP_DECLARE const char * sip_message_get_from_displayname(const sip_message_t * sip)
{
	assert(sip);
	if (NULL == sip->from)return NULL;
	return sip_contact_get_displayname(sip->from);
}

FRANKSIP_DECLARE void sip_message_set_from_displayname(sip_message_t * sip, const char * displayname)
{
	assert(sip);
	assert(sip->from);
	if (NULL == sip->from)
	{
		sip->from = sip_contact_make(sip->pool);
	}
	sip_contact_set_displayname(sip->from, displayname);
}

FRANKSIP_DECLARE const char * sip_message_get_from_host(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->from);
	if (NULL == sip->from)return NULL;
	return sip_contact_get_host(sip->from);
}

/**
FRANKSIP_DECLARE int sip_message_get_from_port(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->from);
	if (NULL == sip->from)return 0;
	return sip_contact_get_port(sip->from);
}
**/
// to.

FRANKSIP_DECLARE void sip_message_set_to_tag(sip_message_t * sip, const char * tag)
{
	assert(sip);
	assert(sip->to);
	if (tag)
	{
		if (NULL == sip->to)
		{
			sip->to = sip_contact_make(sip->pool);
		}
		sip_contact_set_tag(sip->to, tag);
	}
	else
	{
		if (sip->to)
		{
			sip_contact_set_tag(sip->to, 0);
		}
	}
}

FRANKSIP_DECLARE const char * sip_message_get_to_tag(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->to);
	return sip_contact_get_tag(sip->to);
}

FRANKSIP_DECLARE int sip_message_set_to_param(sip_message_t * sip,
	const char * displayname,
	const char * username, const char * host, 
	const char * tag)
{
	assert(sip);
	assert(host);
	assert(username);

	if (NULL == sip->to)
	{
		sip->to = sip_contact_make(sip->pool);
		if (NULL == sip->to) return -1;
	}

	if (NULL != displayname)
	{
		sip_contact_set_displayname(sip->to, displayname);
	}
	sip_contact_set_username(sip->to, username);
	sip_contact_set_domain(sip->to, host, 0);
	if (tag)
	{
		sip_message_set_to_tag(sip, tag);
	}
	return 0;
}


//FRANKSIP_DECLARE int  sip_message_set_to(sip_message_t * sip, sip_to_t * to)
//{
//	sip->to = to;
//	return 0;
//}

//FRANKSIP_DECLARE sip_to_t * sip_message_get_to(const sip_message_t * sip)
//{
//	return sip->to;
//}

FRANKSIP_DECLARE void sip_message_set_to_username(sip_message_t * sip, const char *username)
{
	assert(sip);
	assert(sip->to);
	if (NULL == sip->to)
	{
		sip->to = sip_contact_make(sip->pool);
	}
	sip_contact_set_username(sip->to, username);
}

FRANKSIP_DECLARE const char * sip_message_get_to_username(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->to);
	if (NULL == sip->to)return NULL;
	return sip_contact_get_username(sip->to);
}

FRANKSIP_DECLARE const char * sip_message_get_to_displayname(const sip_message_t * sip)
{
	assert(sip);
	if (NULL == sip->to)return NULL;
	return sip_contact_get_displayname(sip->to);
}

FRANKSIP_DECLARE void sip_message_set_to_displayname(sip_message_t * sip, const char * displayname)
{
	assert(sip);
	assert(sip->to);
	if (NULL == sip->to)
	{
		sip->to = sip_contact_make(sip->pool);
	}
	sip_contact_set_displayname(sip->to, displayname);
}

FRANKSIP_DECLARE const char * sip_message_get_to_host(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->to);
	if (NULL == sip->to)return NULL;
	return sip_contact_get_host(sip->to);
}

/**
FRANKSIP_DECLARE int sip_message_get_to_port(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->to);
	if (NULL == sip->to)return 0;
	return sip_contact_get_port(sip->to);
}
**/

FRANKSIP_DECLARE void sip_message_swap_from_to(sip_message_t * sip)
{
	struct sip_contact_t * tmp = sip->from;
	sip->from = sip->to;
	sip->to = tmp;
}

//FRANKSIP_DECLARE int sip_message_clone_from(sip_message_t * dest, const sip_message_t * src)
//{
//	if (0 == src->from)return -1;
//
//	dest->from = sip_contact_clone(dest->pool, src->from);
//	return 0;
//}

//FRANKSIP_DECLARE int sip_message_clone_to(sip_message_t * dest, const sip_message_t * src)
//{
//	if (0 == src->to)return -1;
//	dest->to = sip_contact_clone(dest->pool, src->to);
//	return 0;
//}
/////

//Contact
FRANKSIP_DECLARE int sip_message_set_contact(sip_message_t * sip, const char * username, const char * host, int port)
{
	assert(sip);
	if (NULL == sip->contact)
	{
		sip->contact = sip_contact_make(sip->pool);
	}
	sip_contact_set_domain(sip->contact, host, port);
	sip_contact_set_username(sip->contact, username);

	return 0;
}

FRANKSIP_DECLARE void sip_message_clone_contact(sip_message_t * sip, const sip_message_t * src)
{
	sip->contact = sip_contact_clone(sip->pool, src->contact);
}

FRANKSIP_DECLARE void sip_message_remove_contact(sip_message_t * sip)
{
	sip->contact = NULL;
}

FRANKSIP_DECLARE const char * sip_message_get_contact_host(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->contact);
	if (NULL==sip->contact)
	{
		return NULL;
	}
	return sip_contact_get_host(sip->contact);
}

FRANKSIP_DECLARE int sip_message_get_contact_port(const sip_message_t * sip)
{
	if (NULL == sip->contact)return 0;
	return sip_contact_get_port(sip->contact);
}

FRANKSIP_DECLARE const char * sip_message_get_contact_username(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->contact);
	if (NULL == sip->contact)return NULL;
	return sip_contact_get_username(sip->contact);
}

FRANKSIP_DECLARE void sip_message_set_contact_param(const sip_message_t * sip, const char * key, const char * value)
{
	assert(sip);
	assert(key);
	assert(value);
	if (0 == sip->contact)return;
	sip_contact_set_param(sip->contact, key, value);
}

FRANKSIP_DECLARE void sip_message_set_contact_uri_param(const sip_message_t * sip, const char * key, const char * value)
{
	if (0 == sip->contact)return;
	if (0 == sip->contact->uri)return;
	sip_uri_set_param(sip->contact->uri, key, value);
}

FRANKSIP_DECLARE const char * sip_message_get_contact_param(const sip_message_t * sip, const char * key)
{
	assert(sip);
	assert(key);
	if (0 == sip->contact)return 0;
	return sip_contact_get_param(sip->contact, key);
}

// Cseq
FRANKSIP_DECLARE int  sip_message_set_cseq(sip_message_t * sip, unsigned int seq, const char * method)
{
	assert(sip);
	if (NULL == sip->cseq)
	{
		sip->cseq = sip_cseq_make(sip->pool);
	}
	sip_cseq_set_method(sip->cseq, method);
	sip_cseq_set_number(sip->cseq, seq);
	return 0;
}

FRANKSIP_DECLARE void sip_message_cseq_set_number(sip_message_t * sip, unsigned int seq)
{
	if (NULL == sip->cseq)
	{
		sip->cseq = sip_cseq_make(sip->pool);
	}
	sip_cseq_set_number(sip->cseq, seq);
}

FRANKSIP_DECLARE void sip_message_cseq_set_method(sip_message_t * sip, const char * method)
{
	if (NULL == sip->cseq)
	{
		sip->cseq = sip_cseq_make(sip->pool);
	}
	sip_cseq_set_method(sip->cseq, method);
}

FRANKSIP_DECLARE const char * sip_message_cseq_get_method(const sip_message_t * sip)
{
	assert(sip);
	assert(sip->cseq);
	if (NULL == sip->cseq)return NULL;
	return sip_cseq_get_method(sip->cseq);
}

FRANKSIP_DECLARE unsigned int sip_message_cseq_get_number(const sip_message_t *sip)
{
	assert(sip);
	assert(sip->cseq);
	if (NULL == sip->cseq)return 0;
	return (unsigned int)sip_cseq_get_number(sip->cseq);
}

FRANKSIP_DECLARE int sip_message_cseq_match(const sip_message_t * sip, const char * method)
{
	assert(sip);
	assert(sip->cseq);
	if (0 == sip->cseq) return -1;
	return apr_strnatcasecmp(method, sip->cseq->cseq_method);
}

// Allow

FRANKSIP_DECLARE void sip_message_set_allows(sip_message_t *sip, const char * allows)
{
	if (allows&&*allows)
	{
		sip->allows = apr_pstrdup(sip->pool, allows);
	}
	else
	{
		sip->allows = NULL;
	}
}

FRANKSIP_DECLARE const char * sip_message_get_allows(const sip_message_t *sip)
{
	return sip->allows;
}

FRANKSIP_DECLARE void sip_message_set_max_forwards(sip_message_t * sip, int max_forwards)
{
	sip->maxforwards = max_forwards;
}

FRANKSIP_DECLARE int  sip_message_get_max_forwards(const sip_message_t * sip)
{
	return sip->maxforwards;
}

FRANKSIP_DECLARE void sip_message_set_session_expires(sip_message_t * sip, unsigned int session_expires, const char * refresher)
{
	if (0 == sip->session_expires)
	{
		sip->session_expires = sip_session_expires_make(sip->pool);
	}
	sip_session_expires_set_expires(sip->session_expires, session_expires);
	if (refresher)
	{
		sip_session_expires_set_refresher(sip->session_expires, refresher);// "uas");
	}
}

FRANKSIP_DECLARE int  sip_message_get_session_expires(sip_message_t * sip, unsigned int * session_expires, const char ** refresher)
{
	if (0 == sip->session_expires)return -1;
	if (session_expires)
	{
		*session_expires = (unsigned int)sip_session_expires_get_expires(sip->session_expires);
	}

	if (refresher)
	{
		*refresher = sip_session_expires_get_refresher(sip->session_expires);
	}

	return 0;
}

FRANKSIP_DECLARE void sip_message_set_supported(sip_message_t * sip, const char * evt)
{
	if (0 == sip->supported)
	{
		sip->supported = sip_supported_make(sip->pool);
	}
	sip_supported_insert(sip->supported, evt);
}

FRANKSIP_DECLARE int  sip_message_has_supported(const sip_message_t * sip, const char * evt)
{
	return sip_supported_exists(sip->supported, evt);
}

//FRANKSIP_DECLARE struct sip_authorization_t * sip_message_get_authorization(const sip_message_t * sip)
//{
//	return sip->auth;
//}

// Headers.
FRANKSIP_DECLARE void sip_message_add_header(sip_message_t * sip, const char * name, const char * value)
{
	// 不能是已知的字段名.
	assert(apr_strnatcmp(name, "From"));
	assert(apr_strnatcmp(name, "To"));
	assert(apr_strnatcmp(name, "Via"));
	assert(apr_strnatcmp(name, "Contact"));
	assert(apr_strnatcmp(name, "CSeq"));
	assert(apr_strnatcmp(name, "Max-Forwards"));
	assert(apr_strnatcmp(name, "Expires"));

	if (name)
	{
		if (value && *value)
		{
			if (0 == sip->headers)
			{
				sip->headers = apr_hash_make(sip->pool);
			}
			apr_hash_set(sip->headers, apr_pstrdup(sip->pool, name), APR_HASH_KEY_STRING, apr_pstrdup(sip->pool, value));
		}
		else if (sip->headers)
		{
			apr_hash_set(sip->headers, name, APR_HASH_KEY_STRING, 0);
		}
	}
}

FRANKSIP_DECLARE const char * sip_message_get_header(const sip_message_t * sip, const char * name)
{
	return apr_hash_get(sip->headers, name, APR_HASH_KEY_STRING);
}

FRANKSIP_DECLARE void sip_message_remove_header(sip_message_t * sip, const char * name)
{
	apr_hash_set(sip->headers, name, APR_HASH_KEY_STRING, 0);
}

FRANKSIP_DECLARE void sip_message_set_body(sip_message_t * sip, const char * body)
{
	if (body && *body)
	{
		sip->body = apr_pstrdup(sip->pool, body);
	}
	else
	{
		sip->body = NULL;
		sip->content_type = NULL;
	}

}

FRANKSIP_DECLARE void sip_message_replace_body(sip_message_t * sip, const char * body, const char * ipv4)
{
	apr_size_t len = 0;
	apr_size_t n = strlen(ipv4);
	char * buf;
	const char * tmp, * str;
	if (NULL == body || '\0' == *body)return;

	len = strlen(body);
	len += n * 2;
	len++;

	buf = apr_palloc(sip->pool, len);
	assert(buf);

/****
v=0
o=FreeSWITCH 1543801061 1543801062 IN IP4 10.250.250.182
s=FreeSWITCH
c=IN IP4 10.250.250.182
t=0 0
m=audio 25892 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
****/

	len = 0;
	str = body;
	while (str)
	{
		tmp = strstr(str, "IN IP4 ");
		if (NULL == tmp) break;

		tmp += 7;
		strncpy(buf + len, str, tmp - str);
		len += (tmp - str);

		strcpy(buf + len, ipv4);
		len += n;

		str = strchr(tmp, '\r');
	}

	if (str)
	{
		strcpy(buf + len, str);
	}
	else
	{
		buf[len++] = 0;
	}

	sip->body = buf;
}

FRANKSIP_DECLARE const char * sip_message_get_body(const sip_message_t * sip)
{
	return sip->body;
}

FRANKSIP_DECLARE int sip_message_get_dtmf(const sip_message_t * sip)
{
	if (sip->body)
	{
		const char * dtmf = strstr(sip->body, "Signal=");
		if (dtmf)
		{
			dtmf += 7;
			if (*dtmf == ' ') dtmf++;
			return (int)*dtmf; // 返回字符 '0','1','2',...'9,'*','#'
		}
	}
	return 0;
}

FRANKSIP_DECLARE void sip_message_copy_headers(sip_message_t * sip, const sip_message_t * src)
{
	// Route-Recorder.
	if (src->record_routes)
	{
		sip->record_routes = sip_route_clone(sip->pool, src->record_routes);
	}
	if (src->routes)
	{
		sip->routes = sip_route_clone(sip->pool, src->routes);
	}
	if (src->session_expires)
	{
		sip->session_expires = sip_session_expires_clone(sip->pool, src->session_expires);
	}
	if (src->supported)
	{
		sip->supported = sip_supported_clone(sip->pool, src->supported);
	}
	sip->min_se = src->min_se;

	if (src->headers)
	{
		// 不能使用apr_hash_copy, 这个只复制hashtable， 不复制内容.
		apr_hash_index_t* hi;
		const char* key, * val;
		sip->headers = apr_hash_make(sip->pool);

		for (hi = apr_hash_first(NULL, src->headers); hi; hi = apr_hash_next(hi))
		{
			apr_hash_this(hi, (void**)& key, NULL, (void**)& val);
			apr_hash_set(sip->headers, apr_pstrdup(sip->pool, key), APR_HASH_KEY_STRING, apr_pstrdup(sip->pool, val));
		}
	}

}

FRANKSIP_DECLARE void sip_message_copy_body(sip_message_t * sip, const sip_message_t * src)
{
	if (src->body && *src->body)
	{
		sip->body = apr_pstrdup(sip->pool, src->body);

		assert(src->content_type);
		if (src->content_type)
		{
			sip->content_type = sip_content_type_clone(sip->pool, src->content_type);
		}
	}
}

FRANKSIP_DECLARE sip_message_t * sip_message_create_request_fwd(
	const sip_message_t * src,
//	const char * method,
//	int seq,
	const char * from_username, const char * from_host, int from_port,
	const char * to_username, const char * to_host, int to_port)
{
	// 作为Proxy创建新的INVITE.
	// 需要保留 From.displayname.
	// 需要保留 扩展的 Header
	const char * from_displayname = sip_message_get_from_displayname(src);
	sip_message_t * sip = sip_message_create_request(src->request_method, 
		src->cseq->cseq_number,
		from_displayname,
		from_username,from_host, from_port,
		to_username, to_host, to_port);
	if (NULL == sip)
		return NULL;

	// 复制其它Headers.
	sip_message_copy_headers(sip, src);

	return sip;
}


FRANKSIP_DECLARE sip_message_t* sip_message_create_request_fwd2(
	const sip_message_t* incoming,
	const sip_message_t* outgoing)
{
	sip_message_t* request = NULL;

	request = sip_message_clone_simple(outgoing);
	if (NULL == request)return NULL;

	// 从outgoing获取 RequestLine, From, To, Via, Contact, Call-ID
	// 从incoming 获取  CSeq, Headers, BODY

	request->cseq = sip_cseq_clone(request->pool, incoming->cseq);

	sip_message_copy_headers(request, incoming);

	if (incoming->body)
	{
		request->content_type = sip_content_type_clone(request->pool, incoming->content_type);
		request->body = apr_pstrdup(request->pool, incoming->body);
	}
	return request;
}

FRANKSIP_DECLARE sip_message_t * sip_message_create_request(const char * method, unsigned int seq,
	const char * from_displayname,
	const char * from_username, const char * from_host, int from_port,
	const char * to_username, const char * to_host, int to_port)
{
	sip_message_t * request = NULL;
	char str[128];

	request = sip_message_create();
	if (NULL == request)return NULL;
	
	// Method
	sip_message_set_method( request, method );

	// first line.
	sip_message_set_request_uri( request, to_username, to_host, to_port );
	
	//Via: 使用本地地址。
	//Via: SIP/2.0/UDP 192.168.1.12:8394;branch=z9hG4bK-d87543-542453839-1--d87543-;rport
	sip_message_insert_top_via( request, from_host, from_port, 1);
	// contact. 此处不产生contact, 需要另外设置.
	// sip_message_set_contact(request, from_username, from_host, from_port);

	// from.
	// From: a11111<sip:13987654321@192.168.2.66>;tag=f132800d
	sip_message_set_from_param( request, from_displayname, from_username, from_host, sip_rand_tag(str));

	// To.
	// To: a11111<sip:13987654321@192.168.2.66>
	sip_message_set_to_param(request, NULL, to_username, to_host, NULL);

	// Call-ID
	// Call-ID: 716b550cf079ef72
	sip_rand_string(str, 24);
	sprintf(str + strlen(str), "@%s", from_host);
	sip_message_set_call_id( request, str);

	// CSeq.
	// CSeq: 1 REGISTER
	sip_message_set_cseq( request, seq, method);

	// Expires: 3600
	//sip_message_set_expires( request, mCfg.nMaxExpires );

	// Max-Forwards: 70
	sip_message_set_max_forwards(request, 70);

	//Allow.
	sip_message_set_allows( request,
		SIP_INVITE SEPARATE
		SIP_ACK SEPARATE
		SIP_CANCEL SEPARATE
		SIP_BYE SEPARATE
		SIP_INFO SEPARATE
	//	SIP_UPDATE SEPARATE
		SIP_OPTIONS );

	// User-Agent: eyeBeam release 3004t stamp 16741
	sip_message_set_user_agent(request, SIP_USER_AGENT);

	return request;
}

FRANKSIP_DECLARE sip_message_t * sip_message_create_register(
	unsigned int seq,
	const char * displayname, const char * username, 
	const char * remotehost, int remoteport, 
	const char * localhost, int localport)
{
	sip_message_t * request;
	char str[50];

	request = sip_message_create();
	if (NULL == request)return NULL;

	//Method
	sip_message_set_method( request, SIP_REGISTER );
	//Request Line.
	sip_message_set_request_uri(request, username, remotehost, remoteport);
	sip_message_set_cseq(request, seq, SIP_REGISTER );


	//Via: 使用本地地址。
	//Via: SIP/2.0/UDP 192.168.1.12:8394;branch=z9hG4bK-d87543-542453839-1--d87543-;rport
	sip_message_insert_top_via( request, localhost, localport, 1);

	//Max-Forwards
	sip_message_set_max_forwards(request, 70);
	//Allow. 此处未进行配置.
	sip_message_set_allows(request, "INVITE, ACK, CANCEL, BYE, INFO, OPTIONS");
	//User-Agent
	sip_message_set_user_agent( request, SIP_USER_AGENT);

	//(4) Contact.
	sip_message_set_contact(request, username, localhost, localport);

	//(5) To.
	//sip_message_set_to(request, sip_contact_create(pszToUsername, pszRemoteHost, nRemotePort));
	//sip_uri_set_param()
	sip_message_set_to_param(request, displayname, username, remotehost, NULL);

	// From.
	sip_message_set_from_param(request, displayname, username, remotehost, sip_rand_tag(str));

	//Call-ID.
	sip_message_set_call_id(request, sip_rand_string(str, 24));


	return request;
}

static const char * sip_get_status_string(int status_code)
{
	struct __status_code_string__
	{
		int code;
		const char * reason;
	};

	static const struct __status_code_string__  reasons[] =
	{
		{0,  "Undefined"},
		{100, "Trying"},
		{180, "Ringing"},
		{181, "Call Is Being Forwarded"},
		{182, "Queued"},
		{183, "Session Progress"},

		{200, "OK"},
		{202, "Accepted"},

		{300, "Multiple Choices"},
		{301, "Moved Permanently"},
		{302, "Moved Temporarily"},
		{305, "Use Proxy"},
		{380, "Alternative Service"},

		{400, "Bad Request"},
		{401, "Unauthorized"},
		{402, "Payment Required"},
		{403, "Forbidden"},
		{404, "Not Found"},
		{405, "Method Not Allowed"},
		{406, "Not Acceptable"},
		{407, "Proxy Authentication Required"},
		{408, "Request Timeout"},
		{409, "Conflict"},
		{410, "Gone"},
		{411, "Length Required"},
		{412, "Conditional Request Failed"},
		{413, "Request Entity Too Large"},
		{414, "Request-URI Too Large"},
		{415, "Unsupported Media Type"},
		{416, "Unsupported Uri Scheme"},
		{420, "Bad Extension"},
		{421, "Extension Required"},
		{422, "Session Interval Too Small"},
		{423, "Interval Too Short"},
		{480, "Temporarily not available"},
		{481, "Call Leg/Transaction Does Not Exist"},
		{482, "Loop Detected"},
		{483, "Too Many Hops"},
		{484, "Address Incomplete"},
		{485, "Ambiguous"},
		{486, "Busy Here"},
		{487, "Request Cancelled"},
		{488, "Not Acceptable Here"},
		{489, "Bad Event"},
		{491, "Request Pending"},
		{493, "Undecipherable"},

		{500, "Internal Server Error"},
		{501, "Not Implemented"},
		{502, "Bad Gateway"},
		{503, "Service Unavailable"},
		{504, "Gateway Time-out"},
		{505, "SIP Version not supported"},

		{600, "Busy Everywhere"},
		{603, "Decline"},
		{604, "Does not exist anywhere"},
		{606, "Not Acceptable"}
	};

	//二分法检索.

	int index = 0;	//默认返回一个
	int begin, end, offset;

	begin = 0;
	end = sizeof(reasons) / sizeof(struct __status_code_string__);

	while (begin != end)
	{
		offset = end - begin;
		offset >>= 1;
		offset += begin;

		if (reasons[offset].code == status_code)
		{
			index = offset;
			break;
		}
		if (reasons[offset].code < status_code)
		{
			begin = offset + 1;
		}
		else
		{
			end = offset;
		}
	}

	return reasons[index].reason;
}

///////////////////////////////////////////////////////////////////////////////////


//头域1.1:To
int  sip_message_parse_to(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->to);

	sip->to = sip_contact_parse(sip->pool, hvalue);
	if (NULL == sip->to)return -1;
	return 0;
}

//头域1.2:From
int  sip_message_parse_from(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->from);
	assert(hvalue);

	sip->from = sip_contact_parse(sip->pool, hvalue);
	return sip->from ? 0 : -1;
}

//头域1.3:Call-ID
int  sip_message_parse_call_id(sip_message_t * sip, char * hvalue)
{
	sip->call_id = apr_pstrdup(sip->pool, hvalue);
	return 0;
}

//头域1.4:CSeq
int  sip_message_parse_cseq(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->cseq);
	assert(hvalue);
	sip->cseq = sip_cseq_parse(sip->pool, hvalue);
	return sip->cseq ? 0 : -1;
}

//头域1.5:Contact
int  sip_message_parse_contact(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->contact);
	assert(hvalue);
	sip->contact = sip_contact_parse(sip->pool, hvalue);
	return sip->contact ? 0 : -1;
}

//头域1.6:Max-Forwards
int  sip_message_parse_max_forward(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	sip->maxforwards = atoi(hvalue);
	return 0;
}

//头域1.7:Via
int  sip_message_parse_via(sip_message_t * sip, char * hvalue)
{
	if (NULL == sip->vias)
	{
		sip->vias = sip_via_parse(sip->pool, hvalue);
	}
	else
	{
		struct sip_via_t * via = sip->vias;
		while (via->next)
		{
			via = via->next;
		}
		assert(NULL == via->next);
		via->next = sip_via_parse(sip->pool, hvalue);
	}

	return 0;
}

static int  sip_message_parse_session_expires(sip_message_t * sip, char * hvalue)
{
	sip->session_expires = sip_session_expires_parse(sip->pool, hvalue);
	return sip->session_expires ? 0 : -1;
}

static int  sip_message_parse_supported(sip_message_t * sip, char * hvalue)
{
	sip->supported = sip_supported_parse(sip->pool, hvalue);
	return sip->supported ? 0 : -1;
}

static int  sip_message_parse_min_session_expires(sip_message_t * sip, char * hvalue)
{
	sip->min_se = atoi(hvalue);
	return 0;
}

int sip_message_parse_user_agent(sip_message_t * sip, char * hvalue)
{
	sip->user_agent = apr_pstrdup(sip->pool, hvalue);
	return 0;
}

//头域2.3:Content-Type
int  sip_message_parse_content_type(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->content_type);
	assert(hvalue);

	sip->content_type = sip_content_type_parse(sip->pool, hvalue);
	return sip->content_type ? 0 : -1;
}

//头域2.4
int  sip_message_parse_allow(sip_message_t * sip, char * hvalue)
{
	//可能存在多行allow. 将其合并.
	sip->allows = apr_pstrdup(sip->pool, hvalue);
	return 0;
}

/*
int  sip_message_parse_rap(sip_message_t * sip, char * hvalue)
{
	//私有的头域.
	//assert( sip->acg == 0 );
//	sip->rap = atoi(hvalue);
	return 0;
}
*/

//以下是每个SIP基本都有的头域:
//头域3.1:Content-Length
int  sip_message_parse_content_length(sip_message_t * sip, char * hvalue)
{
	return 0;
}

//头域3.2:Expires
int  sip_message_parse_expires(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->expires);
	sip->expires = apr_pstrdup(sip->pool, hvalue);
	return 0;
}


//以下是注册时需要的头域:
int  sip_message_parse_authorization(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->auth);

	sip->auth = sip_authorization_parse(sip->pool, hvalue);
	return sip->auth ? 0 : -1;
}

int  sip_message_parse_www_authenticate(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->www);
	sip->www = sip_www_authenticate_parse(sip->pool, hvalue);
	return sip->www ? 0 : -1;
}

int  sip_message_parse_proxy_authenticate(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->proxy_www);
	sip->proxy_www = sip_www_authenticate_parse(sip->pool, hvalue);
	return sip->proxy_www ? 0 : -1;
}

int  sip_message_parse_proxy_authorization(sip_message_t * sip, char * hvalue)
{
	assert(sip);
	assert(NULL == sip->proxy_auth);
	sip->proxy_auth = sip_authorization_parse(sip->pool, hvalue);
	return sip->proxy_auth ? 0 : -1;
}

static int  sip_message_parse_record_route(sip_message_t * sip, char * hvalue)
{
	// <sip:p2.example.com;lr> 
	// <sip:p2.example.com;lr>,<sip:p2.example.com;lr> 
	struct sip_route_t * r = sip_route_parse(sip->pool, hvalue);
	if (r)
	{
		struct sip_route_t * tmp = sip->record_routes;
		if (0 == tmp) sip->record_routes = r;
		else
		{
			while (tmp->next) tmp = tmp->next;
			tmp->next = r;
		}
	}
	return 0;
}

static int  sip_message_parse_route(sip_message_t * sip, char * hvalue)
{
	struct sip_route_t * r = sip_route_parse(sip->pool, hvalue);
	if (r)
	{
		struct sip_route_t * tmp = sip->routes;
		if (0 == tmp) sip->routes = r;
		else
		{
			while (tmp->next) tmp = tmp->next;
			tmp->next = r;
		}
	}
	return 0;
}


FRANKSIP_DECLARE void sip_message_create_authorization(
	sip_message_t * sip, const sip_message_t * src,
	const char * username, const char * password, const char * method)
{
	// From,To,Call-ID都复制过来.
	// 收到 401 时继续组装本包发送.

	sip->from = sip_contact_clone(sip->pool, src->from);
	sip->to = sip_contact_clone(sip->pool, src->to);

	sip_message_set_call_id(sip, sip_message_get_call_id(src));
	sip_message_set_cseq(sip, sip_message_cseq_get_number(src) + 1, method);

	//需要增加认证密码...
	if (src->www)
	{
		//增加密码.
		char buff[128];
		struct sip_www_authenticate_t * www = src->www;
		struct sip_authorization_t * auth = sip_authorization_make(sip->pool);
		if (0 == auth)return;

		sip_uri_to_string(src->to->uri, buff, sizeof(buff));
		sip_authorization_set_param(auth, "Digest", username, www->realm, www->nonce, www->algorithm, buff);
		
		if (www->opaque && www->qop_options)
		{
			sip_rand_string(buff, 16);
			sip_authorization_set_param2(auth, www->qop_options, "00000001", www->opaque, buff);
		}
		//转换密码.
		sip_auth_make_response(auth, method, password, buff);
		sip_authorization_set_response(auth, buff);
		sip->auth = auth;
	}
}

FRANKSIP_DECLARE void sip_message_create_proxy_authorization(sip_message_t * sip, const sip_message_t * src, const char * username, const char * password)
{
	// 收到 407 时组装本包发送.

	char buff[128];
	struct sip_www_authenticate_t * www = src->proxy_www;
	struct sip_authorization_t * auth;

	if (0 == www)
	{
		assert(0);
		return;
	}

	auth = sip_authorization_make(sip->pool);
	if (0 == auth)return;

	// 有些使用www->realm,有些使用to.uri.host
	sip_uri_to_string(src->to->uri, buff, sizeof(buff));
	sip_authorization_set_param(auth, "Digest", username, www->realm, www->nonce, www->algorithm, buff);

	if (www->opaque && www->qop_options)
	{
		sip_rand_string(buff, 16);
		sip_authorization_set_param2(auth, www->qop_options, "00000001", www->opaque, buff);
	}

	//转换密码.
	sip_auth_make_response(auth, SIP_INVITE, password, buff);
	sip_authorization_set_response(auth, buff);

	sip->cseq->cseq_number++;

	sip->proxy_auth = auth;
}


FRANKSIP_DECLARE void sip_message_create_www_authenticate(sip_message_t * sip)
{
	char nonce[36];
	sip_www_authenticate_t * www = sip_www_authenticate_make(sip->pool);
	if (0 == www)return;

	// 根据callid产生nonce.
	sip_auth_convert_callid2nonce(sip_message_get_call_id(sip), nonce);
	sip_www_authenticat_set(www, nonce, sip->to->uri->host);

	sip->www = www;
}


FRANKSIP_DECLARE void sip_message_create_proxy_authenticate(sip_message_t* sip)
{
	char nonce[36];
	sip_www_authenticate_t* www = sip_www_authenticate_make(sip->pool);
	if (0 == www)return;

	// 根据callid产生nonce.
	sip_auth_convert_callid2nonce(sip_message_get_call_id(sip), nonce);
	sip_www_authenticat_set(www, nonce, sip->to->uri->host);

	sip->proxy_www = www;
}

FRANKSIP_DECLARE int  sip_message_authorizate(const sip_message_t * sip, const sip_authorization_t * auth, const char * password)
{
	// 判断nonce是否正确?
	char str[64];

	if (NULL == auth || 0 == auth->nonce || 0 == auth->response)return -1;

	sip_auth_convert_callid2nonce(sip_message_get_call_id(sip), str);
	if (apr_strnatcmp(str, auth->nonce)) return -1;

	sip_auth_make_response(auth, sip->request_method, password, str);
	if (apr_strnatcmp(str, auth->response)) return -1;

	return 0;
}

FRANKSIP_DECLARE const sip_authorization_t * sip_message_get_authorization(const sip_message_t * sip)
{
	return sip->auth;
}

FRANKSIP_DECLARE const sip_from_t * sip_message_get_from(const sip_message_t * sip)
{
	return sip->from;
}

FRANKSIP_DECLARE const sip_to_t * sip_message_get_to(const sip_message_t * sip)
{
	return sip->to;
}

FRANKSIP_DECLARE const sip_contact_t * sip_message_get_contact(const sip_message_t * sip)
{
	return sip->contact;
}

//FRANKSIP_DECLARE const sip_content_type_t * sip_message_get_content_type(const sip_message_t * sip)
//{
//	return sip->content_type;
//}

FRANKSIP_DECLARE const sip_cseq_t * sip_message_get_cseq(const sip_message_t * sip)
{
	return sip->cseq;
}

FRANKSIP_DECLARE const sip_via_t * sip_message_get_topvia(const sip_message_t * sip)
{
	return sip->vias;
}

FRANKSIP_DECLARE const sip_www_authenticate_t * sip_message_get_www_authenticate(const sip_message_t * sip)
{
	return sip->www;
}

FRANKSIP_DECLARE const sip_authorization_t * sip_message_get_proxy_authorization(const sip_message_t * sip)
{
	return sip->proxy_auth;
}

FRANKSIP_DECLARE const char* sip_mesage_get_authorization_username(const sip_authorization_t* auth)
{
	return auth->username;
}
