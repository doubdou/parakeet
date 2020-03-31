#include "parakeet_lua_http.h"
#include "parakeet_lua_base.h"
#include "parakeet_config.h"

#include "parakeet_session.h"
#include "parakeet_core_mysqldb.h"

#define HTTP_DIRECTORY	"../http/"

#define LUAHTTP_METATABLE	"LuaHttp"

typedef struct parakeet_httphandle_t parakeet_httphandle_t;
struct parakeet_httphandle_t
{
	// 需要传入LUA的句柄
	struct evhttp_request* req;
	const struct evhttp_uri* uri;
	struct evbuffer* evb;
	struct evkeyvalq params;
	struct evkeyvalq* headers;// input headers
	int status_code;
	const char * id;
};

struct parakeet_luahttp_t
{
	// http
	struct event_base* base;
	struct evhttp* server;

	apr_thread_t* thread;
	apr_byte_t running;

	struct parakeet_httphandle_t* mt;

	// token
	apr_pool_t* pool;
	apr_hash_t* authorization;
//	apr_hash_t* users;
	apr_time_t last_login;
	apr_thread_mutex_t* mutex;

	// lua
	lua_State* L;
};

struct parakeet_authorization_t
{
	char token[64];
	char username[64];
	char address[32];// 远端的IP地址.
//	ev_uint16_t port;
	apr_time_t expired; // 过期时间
	apr_time_t visited; // 最后登录时间
};

static int  luahttp_init_lua(void);
static int  luahttp_init_http(apr_pool_t* pool, int port);
static void* APR_THREAD_FUNC luahttp_thread_routine(apr_thread_t* thread, void* arg);
static void luahttp_generic_handler(struct evhttp_request* req, void* arg);

static int parakeet_authorization_login(struct evhttp_request* req);
static void parakeet_authorization_logout(struct evhttp_request* req, const char * token);

static void parakeet_reply_error(struct evhttp_request* req, int status_code, const char * phrase);
// 

static int  luahttp_print(lua_State* L);
static int  luahttp_set_status_code(lua_State* L);
static int  luahttp_get_body(lua_State* L);
static int  luahttp_get_param(lua_State* L);
static int  luahttp_get_uri(lua_State* L);
static int  luahttp_get_header(lua_State* L);
static int  luahttp_get_host(lua_State* L);
static int  luahttp_get_id(lua_State* L);
static int  luahttp_add_header(lua_State* L);

//

static int  luahttp_reload_gateway(lua_State* L);
static int  luahttp_delete_gateway(lua_State* L);
static int  luahttp_info_gateway(lua_State* L);
//static int  luahttp_have_gateway(lua_State* L);
static int  luahttp_reload_gateway_group(lua_State* L);
static int  luahttp_delete_gateway_group(lua_State* L);
static int  luahttp_reload_route_caller(lua_State* L);
static int  luahttp_delete_route_caller(lua_State* L);
static int  luahttp_reload_route_rule(lua_State* L);
static int  luahttp_delete_route_rule(lua_State* L);

#if SUPPORT_NUMBER_CONVERT
static int  luahttp_reload_number_convert(lua_State* L);
#endif

#if SUPPORT_PERIOD
static int  luahttp_reload_gateway_period(lua_State* L);
#endif


static int  luahttp_show_gateways(lua_State* L);
static int  luahttp_show_sessions(lua_State* L);
static int  luahttp_show_status(lua_State* L);
static int  luahttp_session_hangup(lua_State* L);
//
static struct parakeet_luahttp_t  _http = { 0 };

int  parakeet_luahttp_initialize(apr_pool_t* pool, int port)
{
	// 单线程启动HTTP服务.
	// 由于HTTP接口调用不频繁,而且不用追求效率, 使用单线程即可.

	memset(&_http, 0, sizeof(struct parakeet_luahttp_t));

	apr_pool_create(&_http.pool, pool);
	apr_thread_mutex_create(&_http.mutex, APR_THREAD_MUTEX_DEFAULT, _http.pool);
	_http.authorization = apr_hash_make(_http.pool);
//	_http.users = apr_hash_make(_http.pool);

	if (0 !=  luahttp_init_lua())
	{
	    dzlog_error("luahttp_init_lua error!");
		return -1;
	}
	
	if (0 != luahttp_init_http(pool, port))
	{
	    dzlog_error("luahttp_init_http error!");
		return -1;
	}
	return 0;
}


static int  luahttp_init_http(apr_pool_t* pool, int port)
{
	_http.base = event_base_new();
	_http.server = evhttp_new(_http.base);
	if (!_http.server)
	{
		dzlog_error("evhttp_new fail");
		return -1;
	}

	if (0 != evhttp_bind_socket(_http.server, "0.0.0.0", (apr_port_t)port))
	{
		dzlog_error("failed to bind port %d", port);
		return -1;
	}

	evhttp_set_gencb(_http.server, luahttp_generic_handler, &_http);
	evhttp_set_default_content_type(_http.server, "application/json;charset=utf-8");

	dzlog_notice("HTTP: server running, port: %d", port);
	_http.running = 1;
	apr_thread_create(&_http.thread, NULL, luahttp_thread_routine, &_http, pool);

	return 0;
}

static void* APR_THREAD_FUNC luahttp_thread_routine(apr_thread_t* thread, void* arg)
{
	event_base_dispatch(_http.base);
	return NULL;
}

void parakeet_luahttp_destroy(void)
{
	dzlog_info("luahttp: destroy");
	_http.running = 0;
	if (_http.base)
	{
		event_base_loopexit(_http.base, NULL);
		_http.base = NULL;
	}
	if (_http.server)
	{
		evhttp_free(_http.server);
		_http.server = NULL;
	}
	if (_http.L)
	{
		lua_close(_http.L);
		_http.L = NULL;
	}
}


static int  luahttp_init_lua(void)
{
	lua_State* L;
	//parakeet_global_config_t * cfg = parakeet_get_config();

	static const luaL_Reg  luahttp_http_driver[] =
	{
		// 写入一行文本
		{ "print",			luahttp_print},

		// 设置返回码,2个参数
		{ "setStatusCode",	luahttp_set_status_code},

		// 设置一个头域
		{ "addHeader",		luahttp_add_header},

		// 当前请求的BODY
		{ "getBody",		luahttp_get_body},

		// 当前请求的URI行参数.
		{ "getParam",		luahttp_get_param},

		// 整个URL行(无参数部分)
		{ "getURI",			luahttp_get_uri},

		// 
		//{ "getRequestParam",luahttp_get_request_param},

		// 获取一个头域信息
		{ "getHeader",		luahttp_get_header},

		// 获取Host地址信息
		{ "getHost",		luahttp_get_host},

		// 获取URL尾部参数.
		{ "getID",  luahttp_get_id},

		// 查询网关状态
		{ "showGateways", luahttp_show_gateways},

		// 查询实时会话信息
		{ "showSessions",	luahttp_show_sessions },

		// 查询运行时状态.
		{ "showStatus",		luahttp_show_status },

		// 挂机命令
		{ "hangup", luahttp_session_hangup },

		{ NULL, NULL }
	};

	static const luaL_Reg  luahttp_parakeet_driver[] =
	{
		// 重新加载网关
		{ "loadGateway",		luahttp_reload_gateway },
		// 删除网关	
		{ "deleteGateway",		luahttp_delete_gateway },
		// 检查网关是否存在.
	//	{ "haveGateway", luahttp_have_gateway},

		// 获取网关状态信息
		// 是否在线, 呼入数, 呼出数, IP地址
		{ "setGateway", luahttp_info_gateway },

		// 重新加载负载均衡/网关组
		{ "loadGatewayGroup", luahttp_reload_gateway_group },
		{ "deleteGatewayGroup", luahttp_delete_gateway_group },

		// 加载主叫路由信息
		{ "loadRouteCaller",	luahttp_reload_route_caller},
		{ "deleteRouteCaller",  luahttp_delete_route_caller},

		// 加载路由规则组
		{ "loadRouteRule",	luahttp_reload_route_rule },	// 加载某组规则组
		{ "deleteRouteRule",  luahttp_delete_route_rule },  // 删除某个规则组

#if SUPPORT_NUMBER_CONVERT
		// 加载号码变换: 主键: 网关名称
		{ "loadGatewayNumberConvert",	luahttp_reload_number_convert },
#endif
#if SUPPORT_PERIOD
		{ "loadGatewayPeriod", luahttp_reload_gateway_period},
#endif

		{ NULL, NULL },
	};

	// 设置环境变量
	(void)putenv("LUA_PATH=" HTTP_DIRECTORY "?.lua;./?.lua");

	L = parakeet_lua_create();
	if (NULL == L) return -1;

	luaL_newlib(L, luahttp_parakeet_driver);
	lua_setglobal(L, "parakeet");

	// 创建一个元表
//	luaL_newlib(L, luahttp_http_driver);
//	lua_setglobal(L, "http");

	// 新建一个元表, 该元表处于堆栈顶部
	luaL_newmetatable(L, LUAHTTP_METATABLE);
	// 在栈顶压入元方法的名称 "__index": 元方法: mt.__index = mt; 
	lua_pushliteral(L, "__index");	// push: __index
	// 在栈顶压入元方法的值: 元表本身 (-1表示栈顶,当前是__index, -2栈顶下面一个数据, 当前是元表 LUA_SESSION_METATABLE)
	lua_pushvalue(L, -2);			// push: metatable
	// 进行赋值操作: 元表(-3位置的LUA_SESSION_METATABLE)的变量(-2位置的__index)赋予值(-1位置的LUA_SESSION_METATABLE)
	// 即操作: metatable.__index = metatable;
	lua_settable(L, -3);
	// 继续设置元表的其它元方法.
	luaL_setfuncs(L, luahttp_http_driver, 0);

	// 创建一个userdata变量, 将保存在 LUA_REGISTRYINDEX 中.
	_http.mt = (parakeet_httphandle_t*)lua_newuserdata(L, sizeof(parakeet_httphandle_t));
	memset(_http.mt, 0, sizeof(struct parakeet_httphandle_t));
	luaL_getmetatable(L, LUAHTTP_METATABLE);	// 获取元表
	lua_setmetatable(L, -2);
	lua_setglobal(L, "http");

	_http.L = L;

	return 0;
}

int  http_reply_file(struct evhttp_request* req, const char* content_type, const char* filename)
{
#if defined(_WIN32)
	apr_file_t* f;
	apr_pool_t* p;
	char* buf;
	struct evbuffer* evb;
	int rv = -1;

	apr_pool_create(&p, 0);


	if (APR_SUCCESS == apr_file_open(&f, filename, APR_FOPEN_READ, 0, p))
	{
		apr_off_t offset = 0;
		apr_file_seek(f, APR_END, &offset);
		buf = (char*)malloc((size_t)offset + 1);
		if (buf)
		{
			apr_size_t bytes = (apr_size_t)offset;
			offset = 0;
			apr_file_seek(f, APR_SET, &offset);
			apr_file_read(f, buf, &bytes);

			evb = evbuffer_new();
			if (evb)
			{

				// 添加一个Headers.
				if (content_type)
				{
					struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
					if (headers)
					{
						evhttp_add_header(headers, "Content-Type", content_type);
					}

				}

				//printf("SendFile: \'%s\', Content-Type: '%s'\n", filename, type?type:"");
				dzlog_info("send file: [%s], content-type:[%s]", filename, content_type ? content_type : "");

				evbuffer_add(evb, buf, bytes);
				evhttp_send_reply(req, HTTP_OK, NULL, evb);
				evbuffer_free(evb);
				rv = 0;
			}
			free(buf);
		}
		apr_file_close(f);

	}
	apr_pool_destroy(p);

	if (0 != rv)
	{
		evhttp_send_error(req, HTTP_NOTFOUND, NULL);
	}

	return rv;
#endif

#if defined(__linux) || defined(__linux__)
	int fd;
	int rv = -1;
	struct evbuffer* evb;

	fd = open(filename, O_RDONLY);
	if (fd > 0)
	{
		if (content_type)
		{
			struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
			if (headers)
			{
				evhttp_add_header(headers, "Content-Type", content_type);
			}
		}

		dzlog_info("send file: [%s], content-type:[%s]", filename, content_type ? content_type : "");

		evb = evbuffer_new();
		if (evb)
		{
			evbuffer_add_file(evb, fd, 0, -1);
			evhttp_send_reply(req, HTTP_OK, NULL, evb);
			evbuffer_free(evb);

			rv = 0;
		}

		close(fd);
	}
	if (0 != rv)
	{
		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
	}

	return rv;
#endif

}


void luahttp_generic_handler(struct evhttp_request* req, void* arg)
{
	// HTTP请求入口函数.

	char buf[1024] = { 0 };
	const struct evhttp_uri* uri;
	const char* url;
	const char* str;
	const char* id = NULL;
	parakeet_httphandle_t* mt = _http.mt;
	struct evkeyvalq* headers;
	struct parakeet_authorization_t* auth;
	struct evhttp_connection* conn;
	char* addr;
	ev_uint16_t port;

	uri = evhttp_request_get_evhttp_uri(req);
	if (NULL == uri)
	{
		dzlog_error("uri is null!");
		return;
	}

	url = evhttp_uri_get_path(uri);
	if (NULL == url)
	{
		dzlog_error("uri is null!");
		return;
	}

#ifdef _DEBUG
	dzlog_debug("URL: %s", url);
#endif

	str = strrchr(url, '.');
	if (str)
	{
		// /help.html
		const char * content_type = NULL;
		str++;
		if (!apr_strnatcasecmp(str, "bmp")) content_type = "application/x-bmp";
		else if (!apr_strnatcasecmp(str, "gif")) content_type = "image/gif";
		else if (!apr_strnatcasecmp(str, "html")) content_type = "text/html";
		else if (!apr_strnatcasecmp(str, "htm")) content_type = "text/html";
		else if (!apr_strnatcasecmp(str, "ico")) content_type = "image/x-icon";
		else if (!apr_strnatcasecmp(str, "jpeg")) content_type = "image/jpeg";
		else if (!apr_strnatcasecmp(str, "jpg")) content_type = "application/x-jpg";
		else if (!apr_strnatcasecmp(str, "png")) content_type = "application/x-png";
		else if (!apr_strnatcasecmp(str, "css")) content_type = "text/css";
		else if (!apr_strnatcasecmp(str, "js")) content_type = "application/x-javascript";

		assert('/' == *url);
		apr_snprintf(buf, sizeof(buf), HTTP_DIRECTORY "pages/%s", url);
		http_reply_file(req, content_type, buf);
		return;
	}

	// 是否有Token字段.
	headers = evhttp_request_get_input_headers(req);
	if (NULL == headers)
	{
		dzlog_error("no header");
		return;
	}
	str = evhttp_find_header(headers, "Token");
	if (NULL == str)
	{
		// 不可以访问.
		if (!strncasecmp(url, HTTP_PREFIX_AAA, sizeof(HTTP_PREFIX_AAA) - 1))
		{
			url += sizeof(HTTP_PREFIX_AAA) - 1;
		}
		if(!strncasecmp(url,  "/v1/voip/aaa", 12))
		{
			switch (evhttp_request_get_command(req))
			{
			case EVHTTP_REQ_POST:
				parakeet_authorization_login(req);
				break;

			case EVHTTP_REQ_DELETE:
				parakeet_authorization_logout(req, url + 13);
				break;

			case EVHTTP_REQ_GET:
				//parakeet_authorization_verify(req);
				break;

			default:
				break;
			}
		}
		else
		{
			parakeet_reply_error(req, 403, "Forbidden");
		}
		return;
	}

	conn = evhttp_request_get_connection(req);
	if (NULL == conn) return;

	evhttp_connection_get_peer(conn, &addr, &port);

	// 检查Token是否存在或过期.
	apr_thread_mutex_lock(_http.mutex);
	auth = apr_hash_get(_http.authorization, str, APR_HASH_KEY_STRING);
	if (auth)
	{
		apr_time_t now = apr_time_now();
		if (auth->expired < now ||
			0 != apr_strnatcmp(addr,auth->address)  )
		{
			auth = NULL;
		}
		else
		{
			// 过期时间, 延长5分钟.
			auth->expired = now + (apr_time_t)parakeet_get_config()->login_timeout * 1000 * 1000;
		}
	}
	apr_thread_mutex_unlock(_http.mutex);
	if (NULL == auth)
	{
		//parakeet_http_reply(req, HTTP_BADREQUEST, 1, "Forbidden");
		parakeet_reply_error(req, 403, "Forbidden");
		return;
	}


	// 如果有后缀,则获得文件返回. 否则作为HTTP接口处理.
	if (!strncasecmp(url, HTTP_PREFIX_PARAKEET, sizeof(HTTP_PREFIX_PARAKEET) - 1))
	{
		url += sizeof(HTTP_PREFIX_PARAKEET) - 1;
	}

	if (*url == '/') url++;
	// 以下支持REST接口的LUA实现.
	switch (evhttp_request_get_command(req))
	{
	case EVHTTP_REQ_GET:
		// 查询数据库?
		apr_snprintf(buf, sizeof(buf), HTTP_DIRECTORY "%s/get.lua", url);
		break;

	case EVHTTP_REQ_POST:
		apr_snprintf(buf, sizeof(buf), HTTP_DIRECTORY "%s/post.lua", url);
		break;

	case EVHTTP_REQ_PUT:
		str = strrchr(url, '/');
		if (str)
		{
			// 是数字.
			id = str;
			id++;

			strcpy(buf, HTTP_DIRECTORY);
			strncpy(buf + sizeof(HTTP_DIRECTORY) - 1, url, str - url);
			strcat(buf, "/put.lua");
		}
		break;

	case EVHTTP_REQ_DELETE:
		str = strrchr(url, '/');
		if (str)
		{
			// 是数字.
			id = str;
			id++;

			strcpy(buf, HTTP_DIRECTORY);
			strncpy(buf + sizeof(HTTP_DIRECTORY) - 1, url, str - url);
			strcat(buf, "/delete.lua");
			str++;
			id = str;
		}
		break;

	default:
		apr_snprintf(buf, sizeof(buf), HTTP_DIRECTORY "pages/notfound.lua");
		break;
	}
	dzlog_debug("HTTP URI: [%s]", buf);

	// 如果文件不存在?

	// 初始化LUA参数.
	mt->req = req;
	mt->uri = uri;
	mt->evb = evbuffer_new();
	mt->headers = evhttp_request_get_input_headers(req);
	mt->status_code = HTTP_OK;	// 默认返回的状态码
	mt->id = id;

	str = evhttp_uri_get_query(uri);
	if (str)
	{
		evhttp_parse_query_str(str, &mt->params);
	}

	evbuffer_expand(mt->evb, 1024);

	if (luaL_dofile(_http.L, buf))
	{
		// 读取和打印脚本错误信息
		str = lua_tostring(_http.L, -1);
		dzlog_error("lua: %s", str);

		evbuffer_drain(mt->evb, evbuffer_get_length(mt->evb));
		evbuffer_add_printf(mt->evb, "{\"code\":1,\"msg\":\"%s\"}", str);
		evhttp_send_reply(req, HTTP_BADREQUEST, NULL, mt->evb);
	}
	else
	{
		evhttp_send_reply(req, mt->status_code, NULL, mt->evb);
	}

	evbuffer_free(mt->evb);
	evhttp_clear_headers(&mt->params);
}


static void parakeet_reply_error(struct evhttp_request* req, int status_code, const char* phrase)
{
	struct evbuffer* evb;

	evb = evbuffer_new();
	evbuffer_add_printf(evb,
		"{\"code\":1,\"msg\":\"%s\"}", phrase);
	evhttp_send_reply(req, status_code, phrase, evb);
	evbuffer_free(evb);
}



int parakeet_authorization_login(struct evhttp_request* req)
{
	struct evbuffer* evb = evhttp_request_get_input_buffer(req);
	const char* body;
	cJSON* json;
	int rv = -1;
	char buf[1024] = { 0 };
	MYSQL_RES* res;
	MYSQL_ROW row;
	unsigned char digest[APR_MD5_DIGESTSIZE] = { 0 };
	int len, i;
	unsigned char c;
	char* str;
	struct parakeet_authorization_t* auth;
	apr_uuid_t uuid;
	apr_hash_index_t* hi;
	apr_time_t now;// , timestamp;
	cJSON* username, * datetime, * sign;
	struct evhttp_connection* conn;

	// 本接口5秒钟调用一次. 连续多次调用将拒绝(简单起见,所有账号使用相同的时间判断).
	now = apr_time_now();

	if (now - _http.last_login < 5000)
	{
		// 不返回, 等超时.
		//evhttp_send_reply(req, 403, "Forbidden", NULL);
		return -1;
	}

	_http.last_login = now;

	evbuffer_add(evb, "\0", 1);
	body = (const char*)evbuffer_pullup(evb, -1);
	if (NULL == body)
	{
//		parakeet_http_reply(req, 1, "No Body");
		parakeet_reply_error(req, HTTP_BADREQUEST, "No Body");
		return -1;
	}

	json = cJSON_Parse(body);
	if (NULL == json)
	{
			parakeet_reply_error(req, HTTP_BADREQUEST, "Bad JSON");
		return -1;
	}

	do
	{
		username = cJSON_GetObjectItem(json, "username");
		if (NULL == username)
		{
			break;
		}
		if (username->type != cJSON_String)
		{
			break;
		}

		datetime = cJSON_GetObjectItem(json, "datetime");
		if (NULL == datetime)
		{
			break;
		}
		if (cJSON_String != datetime->type) break;

		sign = cJSON_GetObjectItem(json, "sign");
		if (NULL == sign) break;
		if (cJSON_String != sign->type) break;

		// 访问数据库, 获取密码.
		apr_snprintf(buf, sizeof(buf) - 1,
			"SELECT `password` FROM `administrator` WHERE `username`='%s';",
			username->valuestring);
		mysql_query(parakeet_mysql_handle(), buf);
		res = mysql_store_result(parakeet_mysql_handle());
		if (NULL == res) break;
		row = mysql_fetch_row(res);
		if (NULL == row)
		{
			mysql_free_result(res);
			break;
		}

		len = apr_snprintf(buf, sizeof(buf) - 1, "%s:%s:%s", username->valuestring, row[0], datetime->valuestring);
		mysql_free_result(res);

		apr_md5(digest, buf, len);

		// 转换为字符串,再比较.
		str = (char*)buf;
		for (i = 0; i < APR_MD5_DIGESTSIZE; i++)
		{
			c = digest[i] >> 4;
			if (c <= 9) *str++ = c + '0';
			else *str++ = 'A' + (c - 10);

			c = digest[i] & 0x0f;
			if (c <= 9)* str++ = c + '0';
			else *str++ = 'A' + (c - 10);
		}
		*str = 0;


		if (apr_strnatcasecmp(buf, sign->valuestring))
			break;

		// 产生token.
		apr_uuid_get(&uuid);
		apr_uuid_format(buf, &uuid);

		conn = evhttp_request_get_connection(req);

		// 扫描所有登录数据, 看看此账号的登录信息.
		apr_thread_mutex_lock(_http.mutex);
		for (hi = apr_hash_first(NULL, _http.authorization); hi; hi = apr_hash_next(hi))
		{
			auth = apr_hash_this_val(hi);
			if (!apr_strnatcmp(auth->username, username->valuestring))
				break;
		}
		if (NULL == hi)
		{
			auth = apr_pcalloc(_http.pool, sizeof(struct parakeet_authorization_t));
			strncpy(auth->username, username->valuestring, sizeof(auth->username) - 1);
		}
		else
		{
			apr_hash_set(_http.authorization, auth->token, APR_HASH_KEY_STRING, NULL);
		}
		strncpy(auth->token, buf, sizeof(auth->token) - 1);

		auth->expired = now + (apr_uint32_t)(parakeet_get_config()->login_timeout * 1000 * 1000);

		if (conn)
		{
			char* addr;
			ev_uint16_t port;
			evhttp_connection_get_peer(conn, &addr, &port);
			strncpy(auth->address, addr, sizeof(auth->address) - 1);
			//auth->port = port;
		}

		apr_hash_set(_http.authorization, auth->token, APR_HASH_KEY_STRING, auth);
		apr_thread_mutex_unlock(_http.mutex);

		evb = evbuffer_new();
		evbuffer_add_printf(evb, 
			"{\"code\":0,"
			"\"msg\":\"OK\","
			"\"data\":\"%s\""
			"}", 
			auth->token);
		evhttp_send_reply(req, HTTP_OK, NULL, evb);
		evbuffer_free(evb);

		rv = 0;

	} while (0);

	cJSON_Delete(json);

	if (0 != rv)
	{
		evhttp_send_error(req, 401, "Unauthorizated");;
	}

	return rv;
}


static void parakeet_authorization_logout(struct evhttp_request* req, const char * token)
{
	struct parakeet_authorization_t* auth;
	int rv = -1;
	apr_thread_mutex_lock(_http.mutex);
	auth = apr_hash_get(_http.authorization, token, APR_HASH_KEY_STRING);
	if (auth)
	{
		auth->expired = apr_time_now();
		rv = 0;
	}
	apr_thread_mutex_unlock(_http.mutex);

	if (0 == rv)
	{
		evhttp_send_reply(req, HTTP_OK, NULL, NULL);
	}
	else
	{
		evhttp_send_reply(req, 403, "Forbidden", NULL);
	}
}

int  luahttp_print(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);

	size_t l;
	const char* str = luaL_optlstring(L, 2, NULL, &l);

	if (str)
	{
		evbuffer_add(mt->evb, str, l);
	}

	return 0;
}

int  luahttp_set_status_code(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	mt->status_code = luaL_optint(L, 2, HTTP_OK);
	return 0;
}

int  luahttp_get_body(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	struct evbuffer* evb = evhttp_request_get_input_buffer(mt->req);
	const char* body;
	size_t l;

	if (NULL == evb)
	{
		return 0;
	}

	l = evbuffer_get_length(evb);

	if (l > 0)
	{
		// evbuffer_add(evb, "\0", 1);
		body = (const char*)evbuffer_pullup(evb, -1);
		if (NULL == body)
		{
			return 0;
		}

		lua_pushlstring(L, body, l);
		return 1;
	}
	return 0;
}

#if 0
int  luahttp_get_request_param(lua_State * L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	const char* str = evhttp_uri_get_query(mt->uri);
	if (str)
	{
		lua_pushstring(L, str);
	}
	else
	{
		lua_pushstring(L, "");
	}
	return 1;
}
#endif

int  luahttp_get_param(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	const char* key = luaL_checkstring(L, 2);
	const char* str = evhttp_find_header(&mt->params, key);
	if (str)
	{
		lua_pushstring(L, str);
	}
	else
	{
		lua_pushnil(L);
	}
	return 1;
}

int  luahttp_get_uri(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	lua_pushstring(L, evhttp_request_get_uri(mt->req));
	return 1;
}

int  luahttp_get_header(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	const char* key = luaL_checkstring(L, 2);
	const char* str = evhttp_find_header(mt->headers, key);
	if (str)
	{
		lua_pushstring(L, str);
	}
	else
	{
		lua_pushnil(L);
	}
	return 1;
}

int  luahttp_get_host(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	lua_pushstring(L, evhttp_request_get_host(mt->req));
	return 1;
}

int  luahttp_get_id(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	if (mt->id) lua_pushstring(L, mt->id);
	else lua_pushnil(L);
	return 1;
}

int  luahttp_add_header(lua_State* L)
{
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	const char* key = luaL_checkstring(L, 2);
	const char* value = luaL_checkstring(L, 3);
	struct evkeyvalq* headers = evhttp_request_get_output_headers(mt->req);

	if (headers)
	{
		evhttp_add_header(headers, key, value);
	}
	return 0;
}


static int  luahttp_reload_gateway(lua_State* L)
{
	//	const char * name = luaL_optstring(L, 1, NULL);

	if (!lua_isnumber(L, 1))
		return 0;
#if 0
	if (0 == parakeet_gateway_reload(lua_tointeger(L, 1)))
	{
		lua_pushboolean(L, 1);
	}
	else
	{
		lua_pushboolean(L, 0);
	}
#endif
    dzlog_info("--- luahttp_reload_gateway --- ");
	return 1;
}

static int  luahttp_delete_gateway(lua_State* L)
{
	if (!lua_isnumber(L, 1))
	{
		assert(0);
		return 0;
	}
#if 0
	parakeet_gateway_delete(lua_tointeger(L, 1));
#endif
	dzlog_info("--- luahttp_delete_gateway --- ");
	return 0;
}

static int  luahttp_info_gateway(lua_State* L)
{
	#if 0
	parakeet_gateway_t* gw;
	int id;

	if (!lua_istable(L, 1))
		return 0;
	lua_getfield(L, 1, "id");
	if (!lua_isnumber(L, -1))
		return 0;
	id = lua_tointeger(L, -1);

	gw = parakeet_gateway_locate_id(id);
	if (gw)
	{
		// 是否在线.
		lua_pushboolean(L, gw->online);
		lua_setfield(L, 1, "online");

		lua_pushinteger(L, gw->fact_incoming_sessions);
		lua_setfield(L, 1, "incoming");

		lua_pushinteger(L, gw->fact_outgoing_sessions);
		lua_setfield(L, 1, "outgoing");

		if (gw->key_sip_address && gw->online)
		{
			lua_pushstring(L, gw->key_sip_address);
			lua_setfield(L, 1, "remote_address");
		}

		parakeet_gateway_unlock(gw);
	}
	else
	{
		lua_pushboolean(L, 0);
		lua_setfield(L, 1, "online");

		lua_pushinteger(L, 0);
		lua_setfield(L, 1, "incoming");

		lua_pushinteger(L, 0);
		lua_setfield(L, 1, "outgoing");
	}
#endif
    dzlog_info("--- luahttp_info_gateway ---");
	return 0;
}

static int  luahttp_reload_gateway_group(lua_State* L)
{
	if (!lua_isnumber(L, 1))
		return 0;
#if 0
	parakeet_loadbalance_reload(lua_tointeger(L, 1));
#endif
	dzlog_info("--- luahttp_reload_gateway_group ---");
	return 0;
}

static int  luahttp_delete_gateway_group(lua_State* L)
{
	// 传入网关组id
	if (!lua_isnumber(L, 1))
		return 0;
#if 0
	parakeet_loadbalance_delete(lua_tointeger(L, 1));
#endif
	dzlog_info("--- luahttp_delete_gateway_group ---");
	return 0;
}

static int  luahttp_reload_route_caller(lua_State* L)
{
	const char* tel = luaL_optstring(L, 1, NULL);
	if (tel)
	{
	#if 0
		parakeet_route_caller_reload(tel);
	#endif
	    dzlog_info("--- luahttp_reload_route_caller ---");
	}
	return 0;
}

static int  luahttp_delete_route_caller(lua_State* L)
{
	const char* tel = luaL_optstring(L, 1, NULL);
	
#if 0
	parakeet_route_caller_delete(tel);
#endif
	dzlog_info("--- luahttp_delete_route_caller %s ---", tel);
	return 0;
}

static int  luahttp_reload_route_rule(lua_State* L)
{
	if (!lua_isnumber(L, 1))
		return 0;
#if 0
	parakeet_route_rule_reload(lua_tointeger(L, 1));
#endif
	dzlog_info("--- luahttp_reload_route_rule ---");
	return 0;
}

static int  luahttp_delete_route_rule(lua_State* L)
{
	if (!lua_isnumber(L, 1))
		return 0;
#if 0
	parakeet_route_rule_delete(lua_tointeger(L, 1));
#endif
	dzlog_info("--- luahttp_delete_route_rule ---");
	return 0;
}

#if SUPPORT_NUMBER_CONVERT
static int  luahttp_reload_number_convert(lua_State* L)
{
	const char* name = luaL_optstring(L, 1, NULL);
	// name是网关.
#if 0
	parakeet_gateway_reload_number_convert(name);
#endif
	dzlog_info("--- luahttp_reload_number_convert ---");
	return 0;
}
#endif

#if SUPPORT_PERIOD
static int luahttp_reload_gateway_period(lua_State* L)
{
	const char* name = luaL_optstring(L, 1, NULL);
#if 0
	parakeet_gateway_reload_period(name);
#endif
	dzlog_info("--- luahttp_reload_gateway_period ---");

	return 0;
}
#endif

static int  luahttp_show_gateways(lua_State* L)
{
	// 查询所有网关的状态.
#if 0
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	const char* str;
	int page = 1;
	int pageSize = 9999;
	int id = -1;

	str = evhttp_find_header(&mt->params, "page");
	if (str) page = atoi(str);

	str = evhttp_find_header(&mt->params, "pageSize");
	if (str) pageSize = atoi(str);

	str = evhttp_find_header(&mt->params, "id");
	if (str) id = atoi(str);

	parakeet_gateway_http_status(mt->evb, page, pageSize, id);
#endif
    dzlog_info("--- luahttp_show_gateways ---");
	return 0;
}

static int  luahttp_show_sessions(lua_State* L)
{
	// 查询会话的信息
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	const char* str;
	int page = 1;
	int pageSize = 9999;
	int gateway_id = -1;
	const char* caller = NULL;
	const char* callee = NULL;
	int dir = 0;
	int status = 0;

	str = evhttp_find_header(&mt->params, "page");
	if (str) page = atoi(str);

	str = evhttp_find_header(&mt->params, "pageSize");
	if (str) pageSize = atoi(str);

	str = evhttp_find_header(&mt->params, "gateway");
	if (str) gateway_id = atoi(str);

	str = evhttp_find_header(&mt->params, "caller");
	if (str) caller = str;

	str = evhttp_find_header(&mt->params, "callee");
	if (str) callee = str;

	str = evhttp_find_header(&mt->params, "direction");
	if (str)
	{
		if (!apr_strnatcasecmp(str, "incoming"))
			dir = 1;
		else if (!apr_strnatcasecmp(str, "outgoing"))
			dir = 2;
	}

	str = evhttp_find_header(&mt->params, "status");
	if (str) status = atoi(str);

	parakeet_session_http_query(mt->evb, page, pageSize, gateway_id, caller, callee, dir, status);
	return 0;
}

static int  luahttp_session_hangup(lua_State* L)
{
	// v1/voip/parakeet/hangup?callid=$callid
	parakeet_httphandle_t* mt = (parakeet_httphandle_t*)luaL_checkudata(L, 1, LUAHTTP_METATABLE);
	const char* uuid;
	uuid = evhttp_find_header(&mt->params, "callid");
	if (NULL == uuid)
		return 0;

#if 0
	parakeet_session_hangup_uuid(uuid);
#endif
    dzlog_info(" --- luahttp_session_hangup ---");
	return 0;
}

static int  luahttp_show_status(lua_State* L)
{
	return 0;
}


