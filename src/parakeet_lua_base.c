#include "parakeet_lua_base.h"
#include "parakeet_config.h"

//http://172.18.221.205:90/voip/SIPProxy.git

// 为该库设置日志驱动函数.
const luaL_Reg  log_driver[] =
{
	{ "info", lua_log_info},
	{ "warn", lua_log_warn},
	{ "error", lua_log_error},
	{ "notice", lua_log_notice},
	{ "debug", lua_log_debug},
	{ "fatal", lua_log_fatal},
	{ NULL, NULL }
};


// 字符串匹配函数.
const luaL_Reg  pattern_driver[] =
{
	{ "match", lua_pattern_match},	// 字符串匹配函数,使用apr_fnmatch
	{ "test",lua_pattern_test},
	{ NULL, NULL }
};


int  lua_log_info(lua_State *L)
{
	// 如果str中有%, 则dzlog_info输出将异常(因为%作为转义使用了)
	const char * str = luaL_optstring(L, 1, 0);
	if (str) dzlog_info(str);
	
	return 0;
}

int  lua_log_warn(lua_State *L)
{
	const char * str = luaL_optstring(L, 1, 0);
	if (str) dzlog_warn(str);
	return 0;
}

int  lua_log_error(lua_State *L)
{
	const char * str = luaL_optstring(L, 1, 0);
	if (str) dzlog_error(str);
	return 0;
}

int  lua_log_notice(lua_State *L)
{
	const char * str = luaL_optstring(L, 1, 0);
	if (str) dzlog_notice(str);
	return 0;
}

int  lua_log_debug(lua_State *L)
{
	const char * str = luaL_optstring(L, 1, 0);
	if (str) dzlog_debug(str);
	return 0;
}

int  lua_log_fatal(lua_State *L)
{
	const char * str = luaL_optstring(L, 1, 0);
	if (str) dzlog_fatal(str);
	return 0;
}


int  lua_pattern_match(lua_State *L)
{
	const char * pattern = luaL_optstring(L, 1, 0);
	const char * str = luaL_optstring(L, 2, 0);

	if (0 == pattern || 0 == str)
	{
		lua_pushboolean(L, 0);
	}
	else
	{
		if (APR_SUCCESS == apr_fnmatch(pattern, str, 0))
		{
			lua_pushboolean(L, 1);
		}
		else
		{
			lua_pushboolean(L, 0);
		}
	}
	return 1;
}

int  lua_pattern_test(lua_State* L)
{
	const char* pattern = luaL_optstring(L, 1, 0);
	if (NULL == pattern || '\0' == *pattern)
	{
		lua_pushboolean(L, 1);
	}
	else
	{
		if (apr_fnmatch_test(pattern))
			lua_pushboolean(L, 1);
		else
			lua_pushboolean(L, 0);
	}
	return 1;

}

lua_State * parakeet_lua_create(void)
{
	// 创建LUA容器, 由于HTTP操作要求实时性不高, 并发也很低,使用单一LUA容器处理所有HTTP请求.
	lua_State * L = luaL_newstate();
	if (NULL == L)return NULL;

	luaL_checkversion(L);
	lua_gc(L, LUA_GCSTOP, 0);  // stop collector during initialization
	luaL_openlibs(L);	// 打开LUA默认的库. 
	lua_gc(L, LUA_GCRESTART, 0);

	parakeet_lua_set_lib(L, log_driver, "log");
	parakeet_lua_set_lib(L, pattern_driver, "pattern");

	do
	{
		// 数据库配置信息.
		// 设置额外变量? parakeet.config["mysql.host"]
		lua_newtable(L);
		lua_pushstring(L, parakeet_get_config()->db_host);
		lua_setfield(L, -2, "host");
		lua_pushinteger(L, parakeet_get_config()->db_port);
		lua_setfield(L, -2, "port");
		lua_pushstring(L, parakeet_get_config()->db_user);
		lua_setfield(L, -2, "user");
		lua_pushstring(L, parakeet_get_config()->db_password);
		lua_setfield(L, -2, "password");
		lua_pushstring(L, parakeet_get_config()->db_name);
		lua_setfield(L, -2, "name");
		lua_setglobal(L, "db");
	} while (0);

	return L;
}

void parakeet_lua_close(lua_State *L)
{
	lua_close(L);
}

void parakeet_lua_set_metatable(lua_State *L, const luaL_Reg * func, const char * name)
{
	// 新建一个元表, 该元表处于堆栈顶部
	luaL_newmetatable(L, name);
	// 在栈顶压入元方法的名称 "__index": 元方法: mt.__index = mt; 
	lua_pushliteral(L, "__index");	// push: __index
	// 在栈顶压入元方法的值: 元表本身 (-1表示栈顶,当前是__index, -2栈顶下面一个数据, 当前是元表 LUA_SESSION_METATABLE)
	lua_pushvalue(L, -2);			// push: metatable
	// 进行赋值操作: 元表(-3位置的LUA_SESSION_METATABLE)的变量(-2位置的__index)赋予值(-1位置的LUA_SESSION_METATABLE)
	// 即操作: metatable.__index = metatable;
	lua_settable(L, -3);
	// 继续设置元表的其它元方法.
	luaL_setfuncs(L, func, 0);
}

void * parakeet_lua_new_metatable(lua_State *L, const char * name, int size)
{
	// 创建一个userdata变量, 将保存在 LUA_REGISTRYINDEX 中.
	void * ud = lua_newuserdata(L, size);
	memset(ud, 0, size);

	luaL_getmetatable(L, name);	// 获取元表
	lua_setmetatable(L, -2);
	return ud;
}

