AC_INIT([parakeet], [1.0], [jinzw_programmer@163.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_RANLIB

AM_PROG_AR

LT_INIT


AC_CONFIG_FILES([
    Makefile
    cJSON/Makefile
    libfranksip/Makefile
    libmpf/Makefile
    liblua5.2/Makefile
    lua_mysql/Makefile
    lua_curl/Makefile
    lua_json/Makefile
    luac/Makefile
    src/Makefile
])
AC_OUTPUT
