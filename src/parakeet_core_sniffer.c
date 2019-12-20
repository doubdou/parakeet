#include "parakeet_config.h"
#include "parakeet_core_sniffer.h"
#include "parakeet_com.h"

static parakeet_sniffer_manager_t * sniffer_globals = 0;


static int rtp_payload_check(const char *data) 
{
	int ret = 0;
	rtp_header_t* hdr = NULL;

	if(data == NULL)
	{
	    return -1;
	}
	hdr = (rtp_header_t*)data;

	switch(hdr->payloadtype)
	{
	  case PT_G729:
	  case PT_PCMA:
	  case PT_PCMU:
	  case PT_RFC2833:
	  	//本系统支持的编码格式
	  	break;
	  case PT_G722:
      case PT_G723: 
	  case PT_L16_1:
	  case PT_L16_2:
	  	
	  default:
          ret = -2;	  
	      break;	
	}


    return ret;
}


static int sip_method_check(const char *data)
{
    char *p;
	char *c;
	char sip_method[10] = "";

	if(data == NULL)
	{
	    return -1;
	}
    memcpy(sip_method, data, sizeof(sip_method) - 1);
    sip_method[sizeof(sip_method) - 1] = ' ';
    p = strchr(sip_method, ' ');
    if (p != NULL) {
       *p = '\0';
       for (c = sip_method; c < p; c++){
            if (!isupper(*c))
                goto fail;
       }
        return 0;
    }
fail:
    return -1;
}

parakeet_errcode_t parakeet_sip_message_entry(uint8_t* data, uint32_t data_len)
{
    parakeet_errcode_t err = PARAKEET_OK;
    sip_message_t* sip     = NULL;
	// 解析SIP消息.
	sip = sip_message_parse((char*)data, (int)data_len);

    dzlog_info("sip %s call-id:%s from:%s to:%s", 
		sip_message_get_method(sip),sip_message_get_call_id(sip), sip_message_get_from_host(sip), sip_message_get_to_host(sip));
    
	return err;
}

parakeet_errcode_t parakeet_rtp_message_entry(uint8_t* data, uint32_t data_len, apr_port_t sport, apr_port_t dport)
{
    parakeet_errcode_t err = PARAKEET_OK;
	rtp_header_t* rtp_hdr  = NULL;
  	uint8_t* media_data    = NULL;

	rtp_hdr = (rtp_header_t*)data;
	media_data = (uint8_t*)&data[RTP_HDR_LENGTH];

	dzlog_info("rtp datalen:%u header_len:%d ver:%u seq:%u payload:%u ssrc:%u media_data:%u", 
		data_len, RTP_HDR_LENGTH, rtp_hdr->version, rtp_hdr->seq, rtp_hdr->payloadtype, rtp_hdr->ssrc, (uint32_t)strlen((char*)media_data));

	return err;
}


static void parakeet_pcaploop_callback(unsigned char* arg, const struct pcap_pkthdr *header, const unsigned char *content)
{
    /* 报文格式 变量定义 */
	eth_header_t* eth_hdr      = NULL;
	ip_header_t* iphdr		   = NULL;
	udp_header_t* udphdr 	   = NULL;
	tcp_header_t* tcphdr 	   = NULL;
	uint32_t ip_hdr_pos        = 0;
	uint32_t udp_hdr_pos       = 0;
	uint32_t tcp_hdr_pos       = 0;
	/* 应用数据 变量定义 */
	uint8_t* data              = NULL;
	int data_len               = 0;
	/* 局部变量 */
    apr_port_t port            = 0; 


    //取得sip监听端口
    port = parakeet_get_config()->port;

 	/* ethernet数据 */
	eth_hdr = (eth_header_t*)content;

    /* ip报文 */
	if(ETH_TYPE_802_1Q == ntohs(eth_hdr->eth_type)){
		ip_hdr_pos = ETH_HDR_LENGTH + ETH_8021Q_TAG_LENGTH;

	}else{
		ip_hdr_pos = ETH_HDR_LENGTH; 
    }

	iphdr  = (ip_header_t*)&content[ip_hdr_pos];

	if(iphdr->protocol == IP_PROTOCOL_NUM_UDP)
	{
	    /* udp */
		udp_hdr_pos = ip_hdr_pos + IP_HDR_LENGTH;
    	udphdr = (udp_header_t*)&content[udp_hdr_pos];
		
		/* 数据 */
		data = (void*)&content[udp_hdr_pos + UDP_HDR_LENGTH];
		data_len = header->len - udp_hdr_pos - UDP_HDR_LENGTH;
	  
	    if(!sip_method_check((char*)data) || !memcmp(data, "SIP/2.0 ", strlen("SIP/2.0 ")))
	 	{
	 	    //SIP报文头,判断报文是请求(method)或者响应("SIP/2.0") 
	 	    //判断监听端口,进入SIP消息处理入口
			if((ntohs(udphdr->sport) == port) || (ntohs(udphdr->dport) == port))
			{   
				parakeet_sip_message_entry(data, data_len);
			}
        } 
		else if(!rtp_payload_check((char*)data) && !((data_len - RTP_HDR_LENGTH) % 10))
        {
			//RTP和RTCP比较类似, 为了将两者报文区分，需要判断有效负载(载荷)类型,再加上另外判断负载的数据大小,区分rtp包
			//RTP消息处理入口.
			parakeet_rtp_message_entry(data, data_len, udphdr->sport, udphdr->dport);
        }
		
	}
	else if(iphdr->protocol == IP_PROTOCOL_NUM_TCP)
	{
	    /* tcp */
		tcp_hdr_pos = ip_hdr_pos + IP_HDR_LENGTH;
		tcphdr = (tcp_header_t*)&content[tcp_hdr_pos];

		/* 数据 */
		data = (void*)&content[tcp_hdr_pos + TCP_HDR_LENGTH];
		data_len = header->len - tcp_hdr_pos - TCP_HDR_LENGTH;
		/* SIP报文头 */
		if(sip_method_check((char*)data) || !memcmp(data, "SIP/2.0 ", strlen("SIP/2.0 ")))
		{
			if((ntohs(tcphdr->sport) == port) || (ntohs(tcphdr->dport) == port))
			{ 
			    parakeet_sip_message_entry(data, data_len);
		    }
		} else{
              //在VoIP通话所用协议中, SIP协议可以选用UDP或TCP        ,        RTP一般只用UDP作为传输的承载
           /* 什么也不做 */   
		}
		
	}else{
	   //其他情况
     /* 什么也不做 */ 
	}

    return;
}

void * APR_THREAD_FUNC parakeet_sniffer_runtime(apr_thread_t * thread, void * param)
{
    int ret = 0;
    //接收报文线程(多线程)
   
	dzlog_notice("Sniffer: thread[%p] running...", thread);
	while (sniffer_globals->running)
	{
	    // 接收消息, 同一时刻只有一个线程会进行包接收操作.
	    apr_thread_mutex_lock(sniffer_globals->packet_mutex);
	    ret = pcap_loop(sniffer_globals->pcap_handle, 1, parakeet_pcaploop_callback, NULL);
		apr_thread_mutex_unlock(sniffer_globals->packet_mutex);
		if(ret < 0){
			 dzlog_error("Sniffer: thread[%p] pcap_loop error!\n", thread);
		}
	}

	return NULL;
}

parakeet_errcode_t parakeet_sniffer_init(apr_pool_t * pool)
{
    parakeet_errcode_t errcode = PARAKEET_OK;
    char errbuf[1024];

    dzlog_notice("initializing sniffer...");

	sniffer_globals = apr_pcalloc(pool, sizeof(*sniffer_globals));

    //内存池创建
    apr_pool_create(&sniffer_globals->pool, pool);	

	// 读写锁
	apr_thread_rwlock_create(&sniffer_globals->session_lock, pool);

	sniffer_globals->next_session_id = 1;
	sniffer_globals->sessions = apr_hash_make(sniffer_globals->pool);

	//实时处理句柄
	sniffer_globals->pcap_handle = pcap_open_live(parakeet_get_config()->nic, 65535, 1, 500, errbuf);
    if(sniffer_globals->pcap_handle == NULL){
		dzlog_error("pcap open live create handle fail(%s).", errbuf);
        return PARAKEET_FAIL;
    }

	// 创建锁: 多线程同时操作网卡时互斥.
	apr_thread_mutex_create(&sniffer_globals->packet_mutex, APR_THREAD_MUTEX_DEFAULT, sniffer_globals->pool);


	// 初始化SIP解析器.
	sip_initialize();

    //以上初始化后，工作线程未启动
	
    return errcode;
}

parakeet_errcode_t parakeet_sniffer_startup(void)
{
	parakeet_errcode_t err = PARAKEET_OK;

	apr_uint32_t i;
	assert(sniffer_globals);

	// 设置运行标记
	sniffer_globals->running = 1;

	sniffer_globals->threads = (apr_thread_t**)apr_pcalloc(sniffer_globals->pool, sizeof(apr_thread_t*)*parakeet_get_config()->thread_number);

	// 逐个创建每个线程
	dzlog_notice("Sniffer: thread number: %d", parakeet_get_config()->thread_number);
	for (i = 0; i < parakeet_get_config()->thread_number; i++)
	{
		apr_thread_create(&sniffer_globals->threads[i], NULL, parakeet_sniffer_runtime, NULL, sniffer_globals->pool);
	}

	// 线程池: 用于处理状态超时任务.
	// 这里又为什么使用线程池? 因为状态机处理线程是一个单一线程, 触发的超时任务不可避免要分配到其它线程处理, 使用线程池比较合适.
	apr_thread_pool_create(&sniffer_globals->state_thread_pool, 4, 16, sniffer_globals->pool);

	// 线程: 状态处理, 扫描所有会话, 检查超时.
	apr_thread_create(&sniffer_globals->state_thread_main, 0, parakeet_session_state_machine, 0, sniffer_globals->pool);

	return err;
}

parakeet_errcode_t parakeet_sniffer_cleanup()
{
	parakeet_errcode_t err = PARAKEET_OK;

    pcap_close(sniffer_globals->pcap_handle);

	return err;
}



