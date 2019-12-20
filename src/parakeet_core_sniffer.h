#ifndef PARAKEET_CORE_SNIFFER_H
#define PARAKEET_CORE_SNIFFER_H

#include <pcap.h>
#include "parakeet_session.h"

typedef struct parakeet_sniffer_manager_t parakeet_sniffer_manager_t;
struct parakeet_sniffer_manager_t
{
	apr_pool_t * pool;					///< 内存池
	apr_hash_t * sessions;				///< 保存所有会话信息. 这个是操作最多的数据.
	apr_thread_rwlock_t * session_lock;	///< 对map加锁

	apr_uint32_t next_session_id;		///< 下一个可用的会话id(全局唯一,历史唯一)
	pcap_t * pcap_handle;               ///< 全局唯一,抓包句柄

	apr_thread_t ** threads;			///< packet消息接收线程
	apr_thread_mutex_t * packet_mutex;	///< packet接收线程互斥锁
	apr_byte_t running;					///< packet接收线程运行标记

	// 状态机
	apr_thread_t * state_thread_main;
	apr_thread_pool_t * state_thread_pool;
};

	
parakeet_errcode_t parakeet_sniffer_init(apr_pool_t * pool);

parakeet_errcode_t parakeet_sniffer_startup(void);

parakeet_errcode_t parakeet_sip_message_entry(uint8_t* data, uint32_t data_len);

parakeet_errcode_t parakeet_rtp_message_entry(uint8_t* data, uint32_t data_len, apr_port_t sport, apr_port_t dport);


#endif
