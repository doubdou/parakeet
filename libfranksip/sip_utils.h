#ifndef SIPVOICE_UTILS_H
#define SIPVOICE_UTILS_H

#ifdef _WIN32 
#pragma   warning(disable: 4996)
#endif

#ifndef PATH_MAX
#define PATH_MAX	256
#endif

#include <apr-1/apr.h>
#include <apr-1/apr_general.h>
#include <apr-1/apr_hash.h>
#include <apr-1/apr_strings.h>
#include <apr-1/apr_pools.h>
#include <apr-1/apr_md5.h>
#include <apr-1/apr_atomic.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

#define SIP_PROTOCOL_VERSION	"SIP/2.0/UDP"
#define SIP_USER_AGENT 	"sipvoice/1.0"

#define SIPVOICE_INTERNAL

#endif
