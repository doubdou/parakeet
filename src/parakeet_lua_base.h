#ifndef PARAKEET_LUA_BASE_H
#define PARAKEET_LUA_BASE_H

#include "parakeet_utils.h"

// 以下是c为lua提供的函数.

// 日志操作函数
int  lua_log_info(lua_State *L);
int  lua_log_warn(lua_State *L);
int  lua_log_error(lua_State *L);
int  lua_log_notice(lua_State *L);
int  lua_log_debug(lua_State *L);
int  lua_log_fatal(lua_State *L);

// 字符串匹配函数
int  lua_pattern_match(lua_State *L);
int  lua_pattern_test(lua_State *L);


lua_State * parakeet_lua_create(void);
void parakeet_lua_close(lua_State *L);


void parakeet_lua_set_metatable(lua_State *L, const luaL_Reg * func, const char * name);
void * parakeet_lua_new_metatable(lua_State *L, const char * name, int size);

// 不能使用函数, 否则func变成指针而非数组, 导致计算长度错误.
#define parakeet_lua_set_lib(L, func, libname) luaL_newlib(L, func); lua_setglobal(L, libname)

#endif
