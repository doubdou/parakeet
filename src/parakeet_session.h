#ifndef PARAKEET_SESSION_H
#define PARAKEET_SESSION_H

enum session_status_t
{
	STATUS_STANDBY = 0,
	STATUS_DESTROY,		///< 等待超时销毁会话

	// 呼入的情况.
	STATUS_IN_INVITE,	///< 收到INVITE, 
	STATUS_IN_TRYING,   ///< 发送100 Trying
	STATUS_IN_RINGING,	///< 发送180 Ringing
	STATUS_IN_ANSWER,	///< 发送200 OK, 等待ACK
	STATUS_IN_TALKING,	///< 收到ACK, 通话中
	STATUS_IN_REFUSE,	///< 发送4xx/5xx/6xx, 等待ACK, 或超时
	STATUS_IN_TX_BYE,	///< 发送BYE, 等 200, 或超时
	STATUS_IN_RX_BYE,	///< 收到BYE, 已发送 200, 等待超时释放.
	STATUS_IN_CANCEL,	///< 收到CANCEL, 发送200, 发送487, 等待ACK.或超时.

	// 呼出的情况.
	STATUS_OUT_INVITE,	///< 发送INVITE
	STATUS_OUT_TRYING,	///< 已收到100 trying
	STATUS_OUT_RINGING,	///< 已收到180 ringing
	STATUS_OUT_ANSWER,	///< 已收到200 OK, 且已发送ACK
	STATUS_OUT_TALKING,	///< 发送ACK, 通话中
	STATUS_OUT_REFUSE,	///< 收到4XX/5XX/6XX拒绝, 已发送ACK, 等待超时释放.
	STATUS_OUT_TX_BYE,	///< 发送BYE, 等待200
	STATUS_OUT_RX_BYE,	///< 收到BYE, 已发送200, 等待超时释放.
	STATUS_OUT_CANCEL,	///< 发送CANCEL, 等待200
	STATUS_OUT_TERMINATED,	///< 等待 487 或超时

};

// 挂机原因.
enum
{
	REASON_UNKNOWN = 0,
	REASON_CALLER_BYE,          // 主叫挂机
	REASON_CALLEE_BYE,          // 被叫挂机
	REASON_USER_BYE,			// 用户挂机
	REASON_USER_CANCEL,			// 主叫取消
	REASON_PROXY_REFUSE,		// 主叫取消时, 代理拒绝
	REASON_NO_ROUTE_RULE,		// 所有路由都不能呼出.
	REASON_INVITE_TIMEOUT,		// 呼叫失败: 等待100Trying超时.
	REASON_RINGING_TIMEOUT,		// 呼叫失败: 等待Ringing超时
	REASON_ANSWER_TIMEOUT,		// 呼叫失败: 等待Answer超时
	REASON_LUA_REFUSE,			// LUA拒绝
	REASON_SESSION_EXPIRES,		// 会话超时了
	REASON_GATEWAY_HUPALL,		// 网关挂机.
	REASON_SESSION_NOT_FOUND,	// 会话不存在
	REASON_LOCAL_TIMEOUT,		// 本地超时, 长时间未接通
	REASON_NO_ACK,				// 应答后未收到ACK.
	REASON_NO_ROUTE_GROUP,		// 没有路由组

	REASON_END_ROUTE,
};

enum session_direction_t
{
	// 呼叫方向
	DIR_TYPE_ANY=0,
	DIR_TYPE_INCOMING,
	DIR_TYPE_OUTGOING,
};


typedef struct parakeet_session_t parakeet_session_t;
struct parakeet_session_t
{
	apr_pool_t * pool;				///< 保存会话信息的内存池, 每个会话使用独立的内存池.

	sip_message_t * invite;			///< 呼入/呼出时的invite
	char * callid;					///< 呼叫id, 从invite消息中获取tag:call-id而得
	apr_port_t local_rtp_port;      ///<本地的媒体(RTP)端口
	char * bridge;					///< 桥接对方的callid, 如果为空,则没有桥接.
	apr_uint32_t ref;				///< 表示本次会话的唯一值, 全局唯一, 历史唯一, 呼入/呼出使用相同的值.
	enum session_direction_t dir;	///< 呼叫方向

	const char * from_username;		///< (初始化后不可变)主叫号码
	const char * to_username;		///< (初始化后不可变)被叫号码
	const char * contact_username;	///< (初始化后不可变)contact的号码,可以为空.
//	const char * remote_username;	///< (初始化后不可变)对端的username, 呼入时为 from_username, 呼出时为 to_username

	enum session_status_t status;	///< (运行时可变)会话的状态
	apr_uint32_t status_duration;	///< (运行时可变)状态status的持续时间(毫秒)
	apr_uint32_t call_timeout;		///< (初始化后不可变)呼叫超时时间(需要转换为毫秒) 使用status_duration计数判断.

#if SUPPORT_TIMER
	apr_uint32_t session_expires;	///< 会话超时计时.(需要转换为微秒)
	apr_uint32_t session_duration;	///< 呼叫计时(通话时与status_duration值相同), 本变量与 session_expires 比较.
#endif

	apr_uint32_t  seq_receiver;		///< 接收到的最后的CSeq.Number
	apr_uint32_t  seq_sender;		///< 发送时使用CSeq.Number
	const char * localhost;			///< 本地的SIP地址.(IP地址)

	// 网关信息.
//	const char * gateway_name;		///< 本会话从哪个网关呼入/呼出
	int	gateway_id;
	const char * gateway_rtp_ip;	///< 网关的外网RTP地址
	apr_byte_t   gateway_is_wlan;	///< 

	//siproxy_route_info_t route;

	// 地址
	apr_sockaddr_t * address;		///< 本会话的SIP远端地址
	const char * local_rtp_ip;		///< RTP地址, 辅助NAT穿透. 从网关复制过来.

	
	// 话单相关记录: 时间信息.
	time_t invite_time;				///< 呼入/呼出时间
	time_t ring_time;				///< 回铃时间,如果没有回铃,则为0
	time_t answer_time;				///< 应答时间,如果没有应答,则为0
	time_t hangup_time;				///< 挂机时间, 任何会话都有挂机时间
	int hangup_cause;				///< 挂机原因, 任何会话都有挂机原因.

	apr_byte_t in_task;				///< 状态机中, 是否在线程中执行任务.

	apr_thread_mutex_t * mutex;		///< 对本会话的互斥锁
	sip_message_t * lastsip;		///< 最后发送的SIP包, 需要重发SIP消息时使用.
};

typedef struct parakeet_session_manager_t parakeet_session_manager_t;
struct parakeet_session_manager_t
{
	apr_pool_t * pool;					///< 内存池
	apr_hash_t * sessions;				///< 保存所有会话信息. 这个是操作最多的数据.
	apr_thread_rwlock_t * session_lock;	///< 对map加锁

	apr_uint32_t next_session_id;		///< 下一个可用的会话id(全局唯一,历史唯一)

    // 状态机
	apr_thread_t * state_thread_main;
	apr_thread_pool_t * state_thread_pool;
};


parakeet_errcode_t parakeet_session_init(apr_pool_t * pool);

void * APR_THREAD_FUNC parakeet_session_state_machine(apr_thread_t * thread, void * param);

parakeet_session_t * parakeet_session_locate(const char * key);

// 设置状态
#define parakeet_session_set_status(_session, _status) _session->status_duration=0; _session->status=_status


parakeet_errcode_t on_parakeet_invite(sip_message_t* sip, packet_direction_t d);

parakeet_errcode_t  on_parakeet_reinvite(parakeet_session_t * session, sip_message_t * sip, packet_direction_t d);

parakeet_errcode_t on_parakeet_ack(sip_message_t* sip);

parakeet_errcode_t on_parakeet_bye(sip_message_t* sip, packet_direction_t d);

parakeet_errcode_t on_parakeet_cancel(sip_message_t* sip);

parakeet_errcode_t on_parakeet_register(sip_message_t* sip);

parakeet_errcode_t on_parakeet_options(sip_message_t* sip);

parakeet_errcode_t on_parakeet_info(sip_message_t* sip);

parakeet_errcode_t on_parakeet_unknown(sip_message_t* sip);

parakeet_errcode_t on_parakeet_trying(sip_message_t* sip);

parakeet_errcode_t on_parakeet_ringing(sip_message_t* sip);

parakeet_errcode_t on_parakeet_answer(sip_message_t* sip);

parakeet_errcode_t on_parakeet_info_ok(sip_message_t* sip);

parakeet_errcode_t on_parakeet_bye_ok(sip_message_t* sip);

parakeet_errcode_t on_parakeet_cancel_ok(sip_message_t* sip);

parakeet_errcode_t on_parakeet_callfail(sip_message_t* sip);

parakeet_errcode_t on_parakeet_terminated(sip_message_t* sip);

parakeet_errcode_t on_parakeet_authentication_required(sip_message_t* sip);

parakeet_errcode_t on_parakeet_transaction_does_not_exist(sip_message_t* sip);


#endif

