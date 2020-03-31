#ifndef PARAKEET_CORE_SNIFFER_H
#define PARAKEET_CORE_SNIFFER_H

#include <pcap.h>
#include "parakeet_session.h"
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netinet/in.h>

typedef struct parakeet_sniffer_manager_t parakeet_sniffer_manager_t;
struct parakeet_sniffer_manager_t
{
    apr_pool_t * pool;
	pcap_t * pcap_handle;               ///< 全局唯一,抓包句柄

	struct sockaddr_in addr;            ///< 网卡设备地址

	apr_thread_t ** threads;			///< packet消息接收线程
	apr_thread_mutex_t * packet_mutex;	///< packet接收线程互斥锁
	apr_byte_t running;					///< packet接收线程运行标记
};

	
parakeet_errcode_t parakeet_sniffer_init(apr_pool_t * pool);

parakeet_errcode_t parakeet_sniffer_startup(void);

parakeet_errcode_t parakeet_sniffer_cleanup(void);

parakeet_errcode_t parakeet_sip_message_entry(uint8_t* data, uint32_t data_len, packet_direction_t d);

parakeet_errcode_t parakeet_rtp_message_entry(uint8_t* data, uint32_t data_len, packet_direction_t d, apr_port_t sport, apr_port_t dport);


#endif
