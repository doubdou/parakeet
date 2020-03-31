#include "parakeet_config.h"
#include "parakeet_core_mysqldb.h"

#define PARAKEET_MYSQL_CDR_MAXROW 100


struct parakeet_mysql_list_t
{
	char * statement;
	struct parakeet_mysql_list_t * next;
};

struct mysql_global_t
{
	// 话单信息结构
	apr_pool_t * p1, *p2;
	apr_thread_mutex_t * mutex;
	apr_thread_t * thread;	    ///< 话单线程
	struct parakeet_mysql_list_t * head;
	struct parakeet_mysql_list_t * tail;
	apr_uint16_t	row_count;  /// 记录数.
	apr_uint16_t	timeout;
	apr_byte_t running;
	MYSQL * cdr_handle;		    ///< MySQL句柄. 为写CDR准备.
	apr_uint16_t cdr_day;		///< 当天话单日期(每月的第几天)
	char cdr_date[24];		    ///< 当天的话单表名称, 格式如: cdr20180101

	MYSQL * handle;
};

static struct mysql_global_t _db = { 0 };

//话单
const char * sql_cdr_format =
"CREATE TABLE IF NOT EXISTS `cdr%04d%02d%02d` ( \
	`id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, \
	`ref` int(11) UNSIGNED NOT NULL, \
	`callid` varchar(64)  NOT NULL, \
	`caller` varchar(18)  NOT NULL, \
	`callee` varchar(18)  NOT NULL, \
	`direction` bit(1) NOT NULL, \
	`gateway_id` int(11) NOT NULL, \
	`invite_time` datetime(0) NOT NULL, \
	`ring_time` datetime(0) DEFAULT NULL, \
	`answer_time` datetime(0) DEFAULT NULL, \
	`hangup_time` datetime(0) NOT NULL, \
	`talk_second` int(11) NOT NULL, \
	`hangup_cause` int(11) NOT NULL, \
	PRIMARY KEY(`id`) USING BTREE \
)ENGINE=InnoDB DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC;";

static void* APR_THREAD_FUNC parakeet_mysql_cdr_routine(apr_thread_t* thread, void* arg);

MYSQL* parakeet_mysql_connect(const char* host, int port, 
	                                            const char* user, const char* passwd, const char * db)
{
	// 连接到mysql数据库. 
	// host: 数据库地址,可以使用域名. (MySQL函数本身支持域名)
	// port: 端口,默认是3306
	// user: 登录的账号,默认root
	// passwd: 登录的密码
	// name: 数据库名称,默认siproxy,允许传入空值.
	MYSQL * handle = NULL;

	if (NULL == host ||
		NULL == user ||
		NULL == passwd)
	{
		dzlog_error("missing mysql parameter");
		return NULL;
	}

	handle = mysql_init(NULL);
	if (NULL == handle)
	{
		dzlog_error("fail: mysql_init");
		return NULL;
	}

	// 连接数据库.
	dzlog_notice("mysql server: %s:%d, auth: %s:%s", host, port, user, passwd);

	if (!mysql_real_connect(handle, host, user, passwd, db, port, NULL, 0))
	{
		dzlog_error("mysql: %s", mysql_error(handle));

		mysql_close(handle);
		return NULL;
	}

	{
		// 设置自动重连
		my_bool reconnect = 1;
		mysql_options(handle, MYSQL_OPT_RECONNECT, &reconnect);
	}

	//dzlog_notice("mysql ready!");

	return handle;
}

parakeet_errcode_t parakeet_mysql_init(apr_pool_t * pool)
{
	char buf[512];
	parakeet_global_config_t * config = parakeet_get_config();

	assert(config);

	if(NULL == config->db_host ||
	   NULL == config->db_user ||
	   NULL == config->db_name || 
	   NULL == config->db_password)
	{
	    dzlog_error("missing mysql parameters!");
		return PARAKEET_STATUS_PARAM_INVALID;
	}

    _db.handle = parakeet_mysql_connect(config->db_host, config->db_port, config->db_user, config->db_password, NULL);
	if(NULL == _db.handle)
		return PARAKEET_STATUS_DATA_ERROR;

    //创建默认数据库
    apr_snprintf(buf, sizeof(buf) - 1, "create database if not exists %s;", config->db_name);
	mysql_query(_db.handle, buf);
    //选择默认数据库
    mysql_select_db(_db.handle, config->db_name);
   
    if(config->cdr_enable){
        _db.running = 1;

	    apr_thread_mutex_create(&_db.mutex, APR_THREAD_MUTEX_DEFAULT, pool);
        apr_thread_create(&_db.thread, 0, parakeet_mysql_cdr_routine, 0, pool);

		apr_pool_create(&_db.p1, pool);
		apr_pool_create(&_db.p2, pool);

		_db.head = _db.tail = NULL;
		_db.row_count = 0;
		_db.timeout = 0;
	}
		
    return PARAKEET_STATUS_OK;
}


void parakeet_mysql_destroy(void)
{
	if (_db.running)
	{
		_db.running = 0;
		if (_db.thread)
		{
			apr_status_t rv;
			apr_thread_join(&rv, _db.thread);
			_db.thread = NULL;
		}
	}
	if (_db.cdr_handle)
	{
		mysql_close(_db.cdr_handle);
		_db.cdr_handle = NULL;
	}
	if (_db.p1)
	{
		apr_pool_destroy(_db.p1);
		_db.p1 = NULL;
	}

	if (_db.p2)
	{
		apr_pool_destroy(_db.p2);
		_db.p2 = NULL;
	}

	if (_db.mutex)
	{
		apr_thread_mutex_destroy(_db.mutex);
		_db.mutex = NULL;
	}


	if (_db.handle)
	{
		mysql_close(_db.handle);
		_db.handle = NULL;
	}
}


static void * APR_THREAD_FUNC parakeet_mysql_cdr_routine(apr_thread_t * thread, void * arg)
{
	// 线程: 从队列获取SQL后执行.

	char buf[1024] = { 0 };
	struct parakeet_mysql_list_t * ptr = NULL;
	apr_time_t now;
	apr_time_t next_update_time = 0;
	apr_time_exp_t exp;

	dzlog_notice("CDR: thread runnnig...");

	assert(_db.mutex);
	assert(_db.thread == thread);
	assert(_db.p1);
	assert(_db.p2);

	while (_db.running)
	{
		// 500 毫秒钟判断一次
		// (1) SQL语句超过100条时立即执行
		// (2) 不满100条, 但超过3秒钟, 则执行
		apr_sleep(500 * 1000);

		_db.timeout++;

		// 定时检查CDR表是否存在.
		now = apr_time_now();
		if (now >= next_update_time)
		{
			apr_time_exp_lt(&exp, now);

			if (exp.tm_mday != _db.cdr_day)
			{
				_db.cdr_day = exp.tm_mday;
				apr_snprintf(_db.cdr_date, sizeof(_db.cdr_date),
					"%d%02d%02d",
					exp.tm_year + 1900,
					exp.tm_mon + 1,
					exp.tm_mday);

				apr_snprintf(buf, sizeof(buf), sql_cdr_format,
					exp.tm_year + 1900, exp.tm_mon + 1, exp.tm_mday);
				if (mysql_query(_db.handle, buf))
				{
					dzlog_warn("SQL: %d:%s", mysql_errno(_db.handle), mysql_error(_db.handle));
				}

				exp.tm_hour = 23;
				exp.tm_min = 59;
				exp.tm_sec = 0;
				apr_time_exp_gmt_get(&next_update_time, &exp);
			}
		}

		apr_thread_mutex_lock(_db.mutex);
		if ((_db.row_count > 0 && _db.timeout >= 6) ||
			(_db.row_count >= PARAKEET_MYSQL_CDR_MAXROW))
		{
			apr_pool_t * p = _db.p1;
			_db.p1 = _db.p2;
			_db.p2 = p;

			apr_pool_clear(_db.p1);

			_db.timeout = 0;
			_db.row_count = 0;

			ptr = _db.head;
			_db.head = _db.tail = NULL;
		}
		apr_thread_mutex_unlock(_db.mutex);

		if (ptr)
		{
			if (NULL == _db.cdr_handle)
			{
				parakeet_global_config_t * cfg = parakeet_get_config();
				_db.cdr_handle = parakeet_mysql_connect(cfg->db_host, cfg->db_port, cfg->db_user, cfg->db_password, cfg->db_name);
				if (NULL == _db.cdr_handle)
					break;
			}

			// 执行缓存的SQL语句.
			mysql_autocommit(_db.cdr_handle, 0);
			while (ptr)
			{
				if (mysql_query(_db.cdr_handle, ptr->statement))
				{
					dzlog_error("mysql: [%d:%s], sql:[%s]", 
						mysql_errno(_db.cdr_handle), mysql_error(_db.cdr_handle), ptr->statement);
				}
				ptr = ptr->next;
			}
			mysql_autocommit(_db.cdr_handle, 1);

			ptr = NULL;
		}
	}

	return 0;
}


const char* parakeet_mysql_cdr_date(void)
{
	return _db.cdr_date;
}


void parakeet_mysql_push(const char * statement)
{
	struct parakeet_mysql_list_t * ptr;

	assert(_db.running);
	if (!_db.running)
		return;

	apr_thread_mutex_lock(_db.mutex);

	ptr = (struct parakeet_mysql_list_t *)apr_palloc(_db.p1, sizeof(struct parakeet_mysql_list_t));
	ptr->next = NULL;
	ptr->statement = apr_pstrdup(_db.p1, statement);

	if (_db.tail)
	{
		_db.tail->next = ptr;
		_db.tail = ptr;
	}
	else
	{
		_db.head = _db.tail = ptr;
	}
	_db.row_count++;
	apr_thread_mutex_unlock(_db.mutex);
}

int parakeet_mysql_query(const char * statement, int(*cb)(MYSQL_RES *, void *), void * arg)
{
	// 返回成功读取的记录数.

	MYSQL_RES * res;
	int rv = -1;

	if (mysql_query(_db.handle, statement))
	{
		//dzlog_error("mysql: %s", mysql_error(_db.handle));
		return -1;
	}

	res = mysql_store_result(_db.handle);
	if (NULL == res)
		return -1;

	//	rs.field = mysql_fetch_fields(rs.res);
	//	rs.col_count = mysql_field_count(_db.handle);
	//	rs.row_count = (unsigned int) mysql_num_rows(rs.res);

	rv = (*cb)(res, arg);

	mysql_free_result(res);

	return rv;
}

MYSQL * parakeet_mysql_handle(void)
{
	assert(_db.handle);
	return _db.handle;
}


const char * parakeet_mysql_error(void)
{
	assert(_db.handle);
	return mysql_error(_db.handle);
}



