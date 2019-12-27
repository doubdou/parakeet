#include "parakeet_config.h"


static parakeet_global_config_t global_config = { 0 };

// 支持本地配置文件.
static int parakeet_config_from_xml(apr_pool_t * pool)
{
	// 打开配置文件../conf/siproxy.xml 读取其中的配置信息.

	apr_file_t * fd;
	apr_xml_doc * doc;
	apr_xml_parser * parser;
	apr_xml_elem * elem;
	apr_xml_elem * ptr;
	apr_pool_t * p;
	apr_status_t rv;
	const char *xmlfile = "../conf/parakeet.xml";

	// 创建临时内存池.
	apr_pool_create(&p, 0);
	if (APR_SUCCESS != apr_file_open(&fd, xmlfile, APR_FOPEN_READ, 0, p))
	{
		dzlog_error("failed to open the xmlfile '%s'", xmlfile);
		apr_pool_destroy(p);
		return -1;
	}

	if (APR_SUCCESS != (rv = apr_xml_parse_file(p, &parser, &doc, fd, 4096)))
	{
		char buf[256];
		dzlog_error("failed to parse file '%s': %s", xmlfile, apr_strerror(rv, buf, sizeof(buf)));

		apr_file_close(fd);
		apr_pool_destroy(p);
		return -1;
	}

	elem = doc->root->first_child;
	while (elem)
	{
		if (!apr_strnatcasecmp(elem->name, "sniffer"))
		{
			// sip配置.
			ptr = elem->first_child;
			while (ptr)
			{
				if (!apr_strnatcasecmp(ptr->name, "port"))
				{
					global_config.port = (apr_port_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				if (!apr_strnatcasecmp(ptr->name, "nic"))
				{
					global_config.nic = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "thread-number"))
				{
					global_config.thread_number = (apr_uint16_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "max-sessions"))
				{
					global_config.max_sessions = (apr_uint32_t)apr_atoi64(ptr->first_cdata.first->text);
					if (global_config.max_sessions >= 200000) global_config.max_sessions = 200000;
				}
				else if (!apr_strnatcasecmp(ptr->name, "call-timeout"))
				{
					global_config.call_timeout = (apr_uint32_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "call-limit"))
				{
					// 使用秒钟.
					global_config.call_limit = (apr_uint32_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "cdr"))
				{
					if (!apr_strnatcasecmp(ptr->first_cdata.first->text, "true"))
					{
						global_config.cdr_enable = 1;
					}
				}
				else if (!apr_strnatcasecmp(ptr->name, "lan"))
				{
					global_config.lan = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "wan"))
				{
					global_config.wan = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				ptr = ptr->next;
			}
		}
		else if (!apr_strnatcasecmp(elem->name, "http"))
		{
			// http配置
			ptr = elem->first_child;
			while (ptr)
			{
				if (!apr_strnatcasecmp(ptr->name, "port"))
				{
					global_config.http_port = (apr_port_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "timeout"))
				{
					global_config.login_timeout = (apr_uint32_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				ptr = ptr->next;
			}
		}
#if 0
		else if (!apr_strnatcasecmp(elem->name, "redis"))
		{
			// redis配置.
			ptr = elem->first_child;
			while (ptr)
			{
				if (!apr_strnatcasecmp(ptr->name, "port"))
				{
					global_config.redis_port = (apr_port_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "host"))
				{
					global_config.redis_host = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "number"))
				{
					global_config.redis_number = (apr_uint16_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				ptr = ptr->next;
			}
		}
#endif
		else if (!apr_strnatcasecmp(elem->name, "notify"))
		{
			ptr = elem->first_child;
			while (ptr)
			{
				if (!apr_strnatcasecmp(ptr->name, "url"))
				{
					global_config.notify_url = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				ptr = ptr->next;
			}
		}
		else if (!apr_strnatcasecmp(elem->name, "mysql"))
		{
			// MySQL配置.
			ptr = elem->first_child;
			while (ptr)
			{
				if (!apr_strnatcasecmp(ptr->name, "host"))
				{
					global_config.db_host = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "name"))
				{
					global_config.db_name = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "user"))
				{
					global_config.db_user = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "password"))
				{
					global_config.db_password = apr_pstrdup(pool, ptr->first_cdata.first->text);
				}
				else if (!apr_strnatcasecmp(ptr->name, "port"))
				{
					global_config.db_port = (apr_port_t)apr_atoi64(ptr->first_cdata.first->text);
				}
				ptr = ptr->next;
			}
		}
		elem = elem->next;
	}

	apr_file_close(fd);
	apr_pool_destroy(p);

//	siproxy_config_default(pool);

	return 0;
}

parakeet_errcode_t parakeet_config_load(apr_pool_t * pool)
{
    parakeet_errcode_t err = PARAKEET_OK;

	err = parakeet_config_from_xml(pool);
	if(err != PARAKEET_OK)
	{
        dzlog_error("parakeet_config_from_xml error (%d)", err);
	    goto done;
	}

done:
    return err;
}

parakeet_global_config_t * parakeet_get_config(void)
{
	return &global_config;
}
