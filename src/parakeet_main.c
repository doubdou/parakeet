#include <stdio.h>
#include "parakeet_config.h"
#include "parakeet_event_socket.h"
#include "parakeet_core_mysqldb.h"
#include "parakeet_core_sniffer.h"
#include "parakeet_session.h"
#include "parakeet_audio.h"


static apr_thread_cond_t * _cond = NULL;
static apr_thread_mutex_t * _mutex = NULL;

static void signal_abort(int sign)
{
	if ((sign == SIGTERM) || (sign == SIGINT))
	{
		printf("Ctrl+C, Closing...\n");
		apr_thread_cond_signal(_cond);
	}
}

static void usage(void)
{
    
}

static int parakeet_main(int argc, char* argv[])
{
	apr_pool_t * pool = 0;
	parakeet_errcode_t errcode = PARAKEET_OK;
	int ret = 0;
	int rv = -1;
	
	// 初始化APR库
	apr_initialize();	
	// 分配内存池
	apr_pool_create(&pool, 0);
	apr_atomic_init(pool);

	// 需要捕获kill消息
	apr_signal(SIGINT, signal_abort);
	apr_signal(SIGTERM, signal_abort);	//用户执行kill命令(或killall)后程序的相应处理
	
    do{
		// 如果没有 ../log 目录则创建.
		apr_dir_make_recursive("../log", APR_UREAD | APR_UWRITE | APR_UEXECUTE, pool);

		// 初始化日志系统, 使用第三方库 zlog 处理日志.
		// 使用前请在系统中先源码安装zlog.
		ret = dzlog_init("../conf/log.conf", "parakeet");
		if (0 != ret)
		{
			printf("log.conf not found (name:parakeet)");
			break;
		}
		
		dzlog_notice("+-------------------------------------+");
		dzlog_notice("| 	   Parakeet                 |");
		dzlog_notice("|            ver 1.0                  |");
		dzlog_notice("| 	   Build "__DATE__ "        |");
		dzlog_notice("+-------------------------------------+");
		dzlog_notice("Parakeet initializing....");

        //读取配置文件
        errcode = parakeet_config_load(pool);
		if(errcode != PARAKEET_OK)
		{
		    dzlog_error("parakeet_config_load error(%d)", errcode);
            break;
	    }
		//初始化数据库
		errcode = parakeet_mysql_init(pool);
		if(errcode != PARAKEET_OK)
		{
		    dzlog_error("parakeet_mysql_init error(%d)", errcode);
            break;
	    }

        //嗅探器
		errcode = parakeet_sniffer_init(pool);
		if(errcode != PARAKEET_OK)
		{
		    dzlog_error("parakeet_sniffer_init error(%d)", errcode);
            break;
	    }

        //sip信令解析
        errcode = parakeet_session_init(pool);
		if(errcode != PARAKEET_OK)
		{
		    dzlog_error("parakeet_session_init error(%d)", errcode);
            break;
	    }		
		//音频解码器
		errcode = parakeet_audio_factory_init(pool);
		if(errcode != PARAKEET_OK)
		{
		    dzlog_error("parakeet_audio_factory_init error(%d)", errcode);
            break;
	    }

        //event socket初始化
		errcode = parakeet_event_socket_init(pool);
		if(errcode != PARAKEET_OK)
		{
		    dzlog_error("parakeet_event_socket_init error(%d)", errcode);
            break;
	    }

        //http服务
        
        //嗅探器启动
		parakeet_sniffer_startup();

		dzlog_notice("Parakeet Service Running...");

		rv = 0;
	}while(0);

	// 命令行, 或等待.
	if (0 == rv)
	{
		apr_thread_cond_create(&_cond, pool);
		apr_thread_mutex_create(&_mutex, APR_THREAD_MUTEX_DEFAULT, pool);
		apr_thread_cond_wait(_cond, _mutex);
	}

	dzlog_info("------------ DESTROY ------------");


    dzlog_notice("BYE!");
		
    return 0;
}


int main(int argc, char* argv[])
{

	if (argc >= 2 && !apr_strnatcmp(argv[1], "--help"))
	{
		usage();
		return 0;
	}


	parakeet_main(argc, argv);

    return 0;
}


