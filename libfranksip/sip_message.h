#ifndef SIP_MESSAGE_H
#define SIP_MESSAGE_H

#ifdef _WIN32 
#ifdef LIBFRANKSIP_EXPORTS
#define FRANKSIP_DECLARE __declspec(dllexport)
#else
#define FRANKSIP_DECLARE __declspec(dllimport)
#endif


#pragma   warning(disable: 4996)

#else
#define FRANKSIP_DECLARE extern
#endif




#define ALLOWS_METHOD "INVITE, ACK, CANCEL, BYE, INFO, OPTIONS"


//常量定义
#define	SIP_SCHEME		"sip"

#define	SIP_INVITE		"INVITE"
#define	SIP_ACK			"ACK"
#define	SIP_BYE			"BYE"
#define	SIP_CANCEL		"CANCEL"
#define	SIP_OPTIONS		"OPTIONS"
#define	SIP_INFO		"INFO"
#define	SIP_UPDATE		"UPDATE"
#define	SIP_REGISTER	"REGISTER"


#define SEPARATE		", "

#define SIP_BRANCH_PREFIX		"z9hG4bK"
#define SIP_BRANCH_LENGTH		7 



// 定义头域.
#define HNAME_FROM					"From"
#define HNAME_TO					"To"
#define HNAME_VIA					"Via"
#define HNAME_CSEQ					"CSeq"
#define HNAME_CONTACT				"Contact"
#define HNAME_ALLOW					"Allow"
#define HNAME_CALL_ID				"Call-ID"
#define HNAME_MAX_FORWARDS			"Max-Forwards"
#define HNAME_EXPIRES				"Expires"
#define HNAME_USER_AGENT			"User-Agent"
#define HNAME_CONTENT_TYPE			"Content-Type"
#define HNAME_CONTENT_LENGTH		"Content-Length"
#define HNAME_AUTHORIZATION			"Authorization"
#define HNAME_WWW_AUTHENTICATE		"WWW-Authenticate"
#define HNAME_REQUIRE				"Require"
#define HNAME_PROXY_AUTHENTICATE	"Proxy-Authenticate"
#define HNAME_PROXY_AUTHORIZATION	"Proxy-Authorization" 
#define HNAME_DIVERSION				"Diversion"		// 某些设备自定义的., 作为原主叫使用.
#define HNAME_SESSION_EXPIRES		"Session-Expires"
#define HNAME_SUPPORTED				"Supported"
#define HNAME_MIN_SESSION_EXPIRES	"Min-SE"

#define HNAME_RECORD_ROUTE			"Record-Route"
#define HNAME_ROUTE					"Route"

// 常见的集中数据类型
#define CONTENT_TYPE_SDP	"application/sdp"
#define CONTENT_TYPE_DTMF	"application/dtmf-relay"
#define CONTENT_TYPE_VIDEO	"application/media_control+xml"


enum
{
	SIP_TRYING = 100,
	SIP_RINGING = 180,
	SIP_CALL_IS_BEING_FORWARDED = 181,
	SIP_QUEUED = 182,
	SIP_SESSION_PROGRESS = 183,
	SIP_OK = 200,
	SIP_ACCEPTED = 202,
	SIP_MULTIPLE_CHOICES = 300,
	SIP_MOVED_PERMANENTLY = 301,
	SIP_MOVED_TEMPORARILY = 302,
	SIP_USE_PROXY = 305,
	SIP_ALTERNATIVE_SERVICE = 380,

	SIP_BAD_REQUEST = 400,
	SIP_UNAUTHORIZED = 401,
	SIP_PAYMENT_REQUIRED = 402,
	SIP_FORBIDDEN = 403,
	SIP_NOT_FOUND = 404,
	SIP_METHOD_NOT_ALLOWED = 405,
	SIP_406_NOT_ACCEPTABLE = 406,
	SIP_PROXY_AUTHENTICATION_REQUIRED = 407,
	SIP_REQUEST_TIME_OUT = 408,
	SIP_GONE = 410,
	SIP_REQUEST_ENTITY_TOO_LARGE = 413,
	SIP_REQUEST_URI_TOO_LARGE = 414,
	SIP_UNSUPPORTED_MEDIA_TYPE = 415,
	SIP_UNSUPPORTED_URI_SCHEME = 416,
	SIP_BAD_EXTENSION = 420,
	SIP_EXTENSION_REQUIRED = 421,
	SIP_SESSION_INTERVAL_TOO_SMALL = 422,
	SIP_INTERVAL_TOO_BRIEF = 423,
	SIP_TEMPORARILY_UNAVAILABLE = 480,
	SIP_CALL_TRANSACTION_DOES_NOT_EXIST = 481,
	SIP_LOOP_DETECTED = 482,
	SIP_TOO_MANY_HOPS = 483,
	SIP_ADDRESS_INCOMPLETE = 484,
	SIP_AMBIGUOUS = 485,
	SIP_BUSY_HERE = 486,
	SIP_REQUEST_TERMINATED = 487,
	SIP_NOT_ACCEPTABLE_HERE = 488,
	SIP_BAD_EVENT = 489,
	SIP_REQUEST_PENDING = 491,
	SIP_UNDECIPHERABLE = 493,

	SIP_INTERNAL_SERVER_ERROR = 500,
	SIP_NOT_IMPLEMENTED = 501,
	SIP_BAD_GATEWAY = 502,
	SIP_SERVICE_UNAVAILABLE = 503,
	SIP_SERVER_TIME_OUT = 504,
	SIP_VERSION_NOT_SUPPORTED = 505,
	SIP_MESSAGE_TOO_LARGE = 513,
	SIP_BUSY_EVRYWHERE = 600,
	SIP_DECLINE = 603,
	SIP_DOES_NOT_EXIST_ANYWHERE = 604,
	SIP_606_NOT_ACCEPTABLE = 606,
};


typedef struct sip_authorization_t sip_authorization_t;
typedef struct sip_contact_t sip_contact_t;
typedef struct sip_contact_t sip_from_t;
typedef struct sip_contact_t sip_to_t;
typedef struct sip_content_type_t sip_content_type_t;
typedef struct sip_cseq_t sip_cseq_t;
typedef struct sip_via_t sip_via_t;
typedef struct sip_www_authenticate_t sip_www_authenticate_t;

typedef struct sip_message_t sip_message_t;

// 初始化处理函数.
FRANKSIP_DECLARE void sip_initialize(void);

// Base.
// 初始化SIP消息
FRANKSIP_DECLARE sip_message_t *  sip_message_create(void);

// 释放SIP消息, SIP必须是一个分配的内存指针
FRANKSIP_DECLARE void sip_message_free(sip_message_t * sip);

// 简单复制SIP消息, 成功返回0,失败返回-1.
FRANKSIP_DECLARE sip_message_t *  sip_message_clone_simple(const sip_message_t * src);

// 准备Response消息.
FRANKSIP_DECLARE sip_message_t *  sip_message_create_response(const sip_message_t * sip, int status_code, const char * phrase);

// 完整复制SIP消息, 成功返回0,失败返回-1.
//FRANKSIP_DECLARE int  sip_message_copy_invite( const sip_message_t * src, sip_message_t ** dest );

// 解析SIP消息, 其中缓存buff内容会被改变.
FRANKSIP_DECLARE sip_message_t *  sip_message_parse( char * buff, int length );

// 验证SIP是否有效.
FRANKSIP_DECLARE int  sip_message_verify(const sip_message_t * sip);
// 将SIP消息转换到字符串, 成功返回字符串长度. 未考虑失败的情况.
FRANKSIP_DECLARE int  sip_message_to_string(const sip_message_t * sip, char * buff, int size);

FRANKSIP_DECLARE const char * sip_rand_string(char * buf, int size);
FRANKSIP_DECLARE const char * sip_rand_tag(char  buf[16]);


FRANKSIP_DECLARE const sip_authorization_t * sip_message_get_authorization(const sip_message_t * sip);
FRANKSIP_DECLARE const sip_from_t * sip_message_get_from(const sip_message_t * sip);
FRANKSIP_DECLARE const sip_to_t * sip_message_get_to(const sip_message_t * sip);
FRANKSIP_DECLARE const sip_contact_t * sip_message_get_contact(const sip_message_t * sip);
FRANKSIP_DECLARE const sip_cseq_t * sip_message_get_cseq(const sip_message_t * sip);
FRANKSIP_DECLARE const sip_via_t * sip_message_get_topvia(const sip_message_t * sip);
FRANKSIP_DECLARE const sip_www_authenticate_t * sip_message_get_www_authenticate(const sip_message_t * sip);
FRANKSIP_DECLARE const sip_authorization_t * sip_message_get_proxy_authorization(const sip_message_t * sip);
FRANKSIP_DECLARE const char* sip_mesage_get_authorization_username(const sip_authorization_t* auth);



// Request & Response.

// 设置SIP消息的Method.
// SIP消息必须已经初始化.
// 函数内自动将status_code设置为0.
// 注意: CSeq中的Method需要另外设置.
FRANKSIP_DECLARE void sip_message_set_method(sip_message_t * sip, const char * method);
FRANKSIP_DECLARE const char * sip_message_get_method(const sip_message_t * sip);


// 设置Response的状态码.
FRANKSIP_DECLARE void sip_message_set_status_code(sip_message_t * sip, int status_code, const char * phrase);
FRANKSIP_DECLARE int sip_message_get_status_code(const sip_message_t * sip);
FRANKSIP_DECLARE const char * sip_message_get_phrase(const sip_message_t * sip);


// 设置Request_uri.
FRANKSIP_DECLARE void sip_message_set_request_uri(sip_message_t * sip, const char * username, const char * host, int port);
FRANKSIP_DECLARE const char * sip_message_get_request_username(const sip_message_t * sip);
FRANKSIP_DECLARE const char * sip_message_get_request_host(const sip_message_t * sip);
FRANKSIP_DECLARE int sip_message_get_request_port(const sip_message_t * sip);

FRANKSIP_DECLARE void sip_message_set_request(sip_message_t * sip, const sip_contact_t * contact);

// User-Agent.
FRANKSIP_DECLARE void sip_message_set_user_agent(sip_message_t * sip, const char * user_agent);
FRANKSIP_DECLARE const char * sip_message_get_user_agent(const sip_message_t * sip);

// Expires.
FRANKSIP_DECLARE void sip_message_set_expires(sip_message_t * sip, int expires);
FRANKSIP_DECLARE int  sip_message_get_expires(sip_message_t * sip);

// Content-Type
FRANKSIP_DECLARE void sip_message_set_content_type(sip_message_t * sip, const char * type);
FRANKSIP_DECLARE int  sip_message_content_type_compare(const sip_message_t * sip, const char * type);
FRANKSIP_DECLARE const char * sip_message_get_content_type(const sip_message_t * sip);

// Via.
FRANKSIP_DECLARE void sip_message_fix_top_via(sip_message_t * sip, const char * host, int port);
FRANKSIP_DECLARE int  sip_message_insert_top_via(sip_message_t * sip, const char * host, int port, int new_branch);
FRANKSIP_DECLARE void sip_message_remove_top_via(sip_message_t * sip);
FRANKSIP_DECLARE void sip_message_set_via_branch(sip_message_t * sip, const char * branch);
FRANKSIP_DECLARE const char* sip_message_get_topvia_branch(const sip_message_t* sip);

////////////////////////////////////////////////////////////////////////////////////////
// call-id.
FRANKSIP_DECLARE void sip_message_set_call_id(sip_message_t * sip, const char * callid);
FRANKSIP_DECLARE const char * sip_message_get_call_id(const sip_message_t * sip);

// From.
FRANKSIP_DECLARE void sip_message_set_from_tag(sip_message_t * sip, const char * tag);
FRANKSIP_DECLARE const char * sip_message_get_from_tag(const sip_message_t * sip);

FRANKSIP_DECLARE int sip_message_set_from_param(sip_message_t * sip, 
	const char * displayname, const char * username, 
	const char * host, const char * tag);

//FRANKSIP_DECLARE int  sip_message_set_from(sip_message_t * sip, sip_from_t * from);
//FRANKSIP_DECLARE sip_from_t * sip_message_get_from(const sip_message_t * sip);

FRANKSIP_DECLARE void sip_message_set_from_username(sip_message_t * sip, const char *username);
FRANKSIP_DECLARE const char * sip_message_get_from_username(const sip_message_t * sip);

FRANKSIP_DECLARE const char * sip_message_get_from_displayname(const sip_message_t * sip);
FRANKSIP_DECLARE void sip_message_set_from_displayname(sip_message_t * sip, const char * displayname);

FRANKSIP_DECLARE const char * sip_message_get_from_host(const sip_message_t * sip);
//FRANKSIP_DECLARE int sip_message_get_from_port(const sip_message_t * sip);


// To.
FRANKSIP_DECLARE void sip_message_set_to_tag(sip_message_t * sip, const char * tag);
FRANKSIP_DECLARE const char * sip_message_get_to_tag(const sip_message_t * sip);

FRANKSIP_DECLARE int sip_message_set_to_param(sip_message_t * sip,
	const char * displayname, const char * username,
	const char * host, const char * tag);

//FRANKSIP_DECLARE int  sip_message_set_to(sip_message_t * sip, sip_to_t * to);
//FRANKSIP_DECLARE sip_to_t * sip_message_get_to(const sip_message_t * sip);

FRANKSIP_DECLARE void sip_message_set_to_username(sip_message_t * sip, const char *username);
FRANKSIP_DECLARE const char * sip_message_get_to_username(const sip_message_t * sip);

FRANKSIP_DECLARE const char * sip_message_get_to_displayname(const sip_message_t * sip);
FRANKSIP_DECLARE void sip_message_set_to_displayname(sip_message_t * sip, const char * displayname);

FRANKSIP_DECLARE const char * sip_message_get_to_host(const sip_message_t * sip);
//FRANKSIP_DECLARE int sip_message_get_to_port(const sip_message_t * sip);

//FRANKSIP_DECLARE int sip_message_clone_from(sip_message_t * dest, const sip_message_t * src);
//FRANKSIP_DECLARE int sip_message_clone_to(sip_message_t * dest, const sip_message_t * src);

FRANKSIP_DECLARE void sip_message_swap_from_to(sip_message_t * sip);

// Contact.
FRANKSIP_DECLARE int  sip_message_set_contact(sip_message_t * sip, const char * username, const char * host, int port);
FRANKSIP_DECLARE void sip_message_remove_contact(sip_message_t * sip);
FRANKSIP_DECLARE void sip_message_clone_contact(sip_message_t * sip, const sip_message_t * src);

FRANKSIP_DECLARE const char * sip_message_get_contact_host(const sip_message_t * sip);
FRANKSIP_DECLARE int sip_message_get_contact_port(const sip_message_t * sip);
FRANKSIP_DECLARE const char * sip_message_get_contact_username(const sip_message_t * sip);

FRANKSIP_DECLARE void sip_message_set_contact_param(const sip_message_t * sip, const char * key, const char * value);
FRANKSIP_DECLARE const char * sip_message_get_contact_param(const sip_message_t * sip, const char * key);
FRANKSIP_DECLARE void sip_message_set_contact_uri_param(const sip_message_t * sip, const char * key, const char * value);

// CSeq.
FRANKSIP_DECLARE int  sip_message_set_cseq(sip_message_t * sip, unsigned int seq, const char * method);
FRANKSIP_DECLARE void sip_message_cseq_set_number(sip_message_t * sip, unsigned int seq);
FRANKSIP_DECLARE void sip_message_cseq_set_method(sip_message_t * sip, const char * method);
FRANKSIP_DECLARE const char * sip_message_cseq_get_method(const sip_message_t * sip);
FRANKSIP_DECLARE unsigned int sip_message_cseq_get_number(const sip_message_t *sip);
FRANKSIP_DECLARE int sip_message_cseq_match(const sip_message_t * sip, const char * method);

// Allow.
FRANKSIP_DECLARE void sip_message_set_allows(sip_message_t *sip, const char * allows);
FRANKSIP_DECLARE const char * sip_message_get_allows(const sip_message_t *sip);

// Max-Forwards.
FRANKSIP_DECLARE void sip_message_set_max_forwards(sip_message_t * sip, int max_forwards);
FRANKSIP_DECLARE int  sip_message_get_max_forwards(const sip_message_t * sip);


// Session-Expires
FRANKSIP_DECLARE void sip_message_set_session_expires(sip_message_t * sip, unsigned int session_expires, const char * refresher);
FRANKSIP_DECLARE int  sip_message_get_session_expires(sip_message_t * sip, unsigned int * session_expires, const char ** refresher);
FRANKSIP_DECLARE void sip_message_set_supported(sip_message_t * sip, const char * evt);
FRANKSIP_DECLARE int  sip_message_has_supported(const sip_message_t * sip, const char * evt);
////////////////////////////////////////////////////////////////////////////////////////

// Authorization
//FRANKSIP_DECLARE struct sip_authorization_t * sip_message_get_authorization(const sip_message_t * sip);

////////////////////////////////////////////////////////////////////////////////////////
// Headers.
FRANKSIP_DECLARE void sip_message_add_header(sip_message_t * sip, const char * name, const char * value);
FRANKSIP_DECLARE const char * sip_message_get_header(const sip_message_t * sip, const char * name);
FRANKSIP_DECLARE void sip_message_remove_header(sip_message_t * sip, const char * name);


////////////////////////////////////////////////////////////////////////////////////////
// sdp.
FRANKSIP_DECLARE void sip_message_set_body( sip_message_t * sip, const char * body );
FRANKSIP_DECLARE const char * sip_message_get_body(const sip_message_t * sip);
FRANKSIP_DECLARE void sip_message_replace_body(sip_message_t * sip, const char * body, const char * ipv4);

FRANKSIP_DECLARE int sip_message_get_dtmf(const sip_message_t * sip);


//////////////////////////////////////////////////////////////////////////

FRANKSIP_DECLARE void sip_message_copy_headers(sip_message_t * dest, const sip_message_t * src);
FRANKSIP_DECLARE void sip_message_copy_body(sip_message_t * dest, const sip_message_t * src);


// 创建原始请求(UAC使用)
FRANKSIP_DECLARE sip_message_t * sip_message_create_request(const char * method, unsigned int seq, 
	const char * from_displayname,
	const char * from_username, const char * from_host, int from_port,
	const char * to_username, const char * to_host, int to_port);

// 创建Proxy请求(Proxy情况下的UAC使用)
FRANKSIP_DECLARE sip_message_t * sip_message_create_request_fwd(
	const sip_message_t * src,
	const char * from_username, const char * from_host, int from_port,
	const char * to_username, const char * to_host, int to_port);

FRANKSIP_DECLARE sip_message_t* sip_message_create_request_fwd2(
	const sip_message_t* incoming,
	const sip_message_t* outgoing);

#define sip_message_create_invite(__seq, __from_phone, __from_host, __from_port, __to_phone, __to_host, __to_port)	\
	sip_message_create_request(SIP_INVITE, __seq, NULL, __from_phone, __from_host, __from_port, __to_phone, __to_host, __to_port)

#define sip_message_create_options(__seq, __username, __remotehost, __remoteport, __localhost, __localport) \
	sip_message_create_request(SIP_OPTIONS, __seq, NULL, __username, __localhost, __localport, __username, __remotehost, __remoteport)

// 建立一个INVITE.
/***
FRANKSIP_DECLARE sip_message_t * sip_message_build_invite( int seq,
	const char * from_phone, const char * from_host, int from_port,
	const char * to_phone, const char * to_host, int to_port );
	***/

FRANKSIP_DECLARE sip_message_t * sip_message_create_register( unsigned int seq,
	const char * displayname, const char * username, 
	const char * remotehost, int remoteport, 
	const char * localhost, int localport);



// 为sip增加鉴权信息.
// 再次发送 REGISTER:需要带Auth信息
FRANKSIP_DECLARE void sip_message_create_authorization(
		sip_message_t * sip, const sip_message_t * src,
		const char * username, const char * password, const char * method);


// 为SIP增加鉴权信息.
// 再次发送INVITE: 需要带Auth的消息.
FRANKSIP_DECLARE void sip_message_create_proxy_authorization(sip_message_t * sip, const sip_message_t * src, const char * username, const char * password);


// 返回401: 需要增加WWW-Auth...
FRANKSIP_DECLARE void sip_message_create_www_authenticate(sip_message_t * sip);
FRANKSIP_DECLARE void sip_message_create_proxy_authenticate(sip_message_t* sip);

// 收到有Auth的需要检查签名
FRANKSIP_DECLARE int  sip_message_authorizate(const sip_message_t* sip, const sip_authorization_t* auth, const char* password);

#endif
