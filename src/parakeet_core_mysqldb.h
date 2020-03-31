#ifndef PARAKEET_CORE_MYSQLDB_H
#define PARAKEET_CORE_MYSQLDB_H

MYSQL* parakeet_mysql_connect(const char* host, int port, 
	                                            const char* user, const char* passwd, const char * db);
parakeet_errcode_t parakeet_mysql_init(apr_pool_t * pool);

void parakeet_mysql_destroy(void);

const char* parakeet_mysql_cdr_date(void);

void parakeet_mysql_push(const char * statement);

int parakeet_mysql_query(const char * statement, int(*cb)(MYSQL_RES *, void *), void * arg);

// 获取MySQL的的句柄
MYSQL * parakeet_mysql_handle(void);

const char * parakeet_mysql_error(void);

#endif
