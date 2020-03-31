#include "parakeet_config.h"
#include "parakeet_session.h"
#include "parakeet_stream.h"
#include "parakeet_core_mysqldb.h"

static parakeet_session_manager_t * session_globals = 0;

static const char* const SESSION_STATUS_STRING[] = 
{
	"STANDBY",	// 空闲
	"DESTROY",	// 释放中
	"INCOMING",	// 呼入中
	"RINGBACK",	// 呼入振铃中
	"ANSWER",	// 呼入应答
	"TALKING",  // 呼入通话中
	"REFUSE",	// 呼入被拒绝
	"HANGUP",	// 挂机中
	"USER HANGUP",	// 主叫方挂机
	"CANCEL",		// 主叫方取消呼叫

	// 呼出的情况.
	"OUTGOING",		// 呼出中
	"TRYING",		// 呼出已确认
	"RINGING",		// 呼出回铃
	"ANSWER",		// 呼出已应答
	"CALL FAILED",	// 呼出失败
	"HANGUP",		// 挂机
	"USER HANGUP",	// 被叫方挂机
	"CANCEL",		// 本方取消

	"TERMINATED"	// 呼叫被终止
};

parakeet_errcode_t parakeet_session_init(apr_pool_t * pool)
{
	parakeet_errcode_t errcode = PARAKEET_STATUS_OK;

	dzlog_notice("initializing session manager...");

	session_globals = apr_pcalloc(pool, sizeof(*session_globals));

	//内存池创建
	apr_pool_create(&session_globals->pool, pool);	

	// 读写锁
	apr_thread_rwlock_create(&session_globals->session_lock, pool);

	session_globals->next_session_id = 1;
	session_globals->running = 1;
	session_globals->sessions = apr_hash_make(session_globals->pool);
	
	// 线程池: 用于处理状态超时任务.
	// 这里为什么使用线程池? 因为状态机处理线程是一个单一线程, 触发的超时任务不可避免要分配到其它线程处理, 使用线程池比较合适.
	apr_thread_pool_create(&session_globals->state_thread_pool, 4, 16, session_globals->pool);

	// 线程: 状态处理, 扫描所有会话, 检查超时.
	
	apr_thread_create(&session_globals->state_thread_main, 0, parakeet_session_state_machine, 0, session_globals->pool);

	return errcode;
}

void parakeet_session_destroy(void)
{
	// 销毁会话.
	if (session_globals)
	{
		if (session_globals->sessions)
		{
			apr_hash_index_t * hi;
			parakeet_session_t * session;

			dzlog_info("destroy sessions");
			for (hi = apr_hash_first(0, session_globals->sessions); hi; hi = apr_hash_next(hi))
			{
				session = apr_hash_this_val(hi);
				if (session->invite) sip_message_free(session->invite);
				apr_pool_destroy(session->pool);
			}
			apr_hash_clear(session_globals->sessions);
		}
		apr_pool_destroy(session_globals->pool);
		session_globals->running = 0;
	}
}


void * APR_THREAD_FUNC parakeet_session_state_machine(apr_thread_t * thread, void * param)
{
	// 会话状态处理.判断超时情况.
	
	apr_hash_index_t * hi;
	apr_time_t now, last;
	apr_uint32_t interval;
	//apr_uint32_t call_limit = parakeet_get_config()->call_limit * 1000;// 转换为毫秒.
	parakeet_session_t * session;

//#ifdef _DEBUG
//  static unsigned int __seq__ = 0;
//#endif

	dzlog_notice("StateMachine: thread[%p] running...", thread);

    last = apr_time_now() / 1000;
	while(session_globals->running)
	{
        now = apr_time_now();

		now /= 1000;

		interval = (apr_uint32_t)(now - last);   //使用毫秒(ms)
		last = now;

		apr_thread_rwlock_rdlock(session_globals->session_lock);
		for (hi = apr_hash_first(0, session_globals->sessions); hi; hi = apr_hash_next(hi))
		{
		    session = apr_hash_this_val(hi);
		    session->status_duration += interval;

			if (APR_SUCCESS == apr_thread_mutex_trylock(session->mutex))
			{
				switch (session->status)
				{
				   case STATUS_DESTROY:
				   				// 销毁会话.
				       parakeet_execute_task(on_session_timeout_destroy);
				       break;
				   default:
				   	   break;
				}
				apr_thread_mutex_unlock(session->mutex);
			}
		}


		apr_thread_rwlock_unlock(session_globals->session_lock);


#define TIMER_INTERVAL		1000	// 会话状态机间隔时间.
		// 如果消息太多, 则延时短一点.
		// 根据上一次的间隔,调整本次间隔. 
		if (interval < TIMER_INTERVAL)
		{
			apr_sleep(TIMER_INTERVAL * 1000);
		}
		else if (interval < 2* TIMER_INTERVAL)	// 延时1500的话, 本地只需要sleep 500
		{
			// 毫秒到微秒.
			apr_sleep((2 * TIMER_INTERVAL - (apr_interval_time_t)interval) * 1000);
		}
		else
		{
			dzlog_warn("!!!session state machine busy, interval:%u!!!", interval);
		}		
	}

	dzlog_notice("StateMachine: thread[%p] exit...", thread);
    return NULL;
}

parakeet_session_t * parakeet_session_locate(const char * key)
{
	// 根据callid 查找会话.且加锁.key
	parakeet_session_t * session = 0;

	assert(key);
	apr_thread_rwlock_rdlock(session_globals->session_lock);
	session = apr_hash_get(session_globals->sessions, key, APR_HASH_KEY_STRING);
	if (session)
	{
		// 如果此处死锁, 将导致 globals->session_lock 被锁.
		apr_thread_mutex_lock(session->mutex);
	}

	apr_thread_rwlock_unlock(session_globals->session_lock);
	return session;
}

void parakeet_session_unlock(parakeet_session_t * session)
{
	assert(session);
	apr_thread_mutex_unlock(session->mutex);
}


parakeet_errcode_t on_parakeet_invite(sip_message_t* sip, packet_direction_t d)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	// 核心函数: 呼叫请求处理

	parakeet_session_t* session = NULL;
	apr_pool_t* pool = NULL;
	const char* callid = NULL;
	const char* caller = NULL;
	const char* callee = NULL;
	//char ip[32] = { 0 };
	//char uri[64] = { 0 };
	int rv = -1;

	///////////////////////////////////////////////////////////////
	// sent-by:branch决定事务
	// callid,from.tag 决定对话.

	callid = sip_message_get_call_id(sip);

	// 不能无限制创建大量会话信息, 必须判断成功后再创建会话.
	session = parakeet_session_locate(callid);

    if(NULL != session)
	{
		const char* tag = sip_message_get_from_tag(sip);
		assert(session->invite);
		//assert(session->address);
		assert(session->from_username);
		assert(tag);
		if (NULL == tag)
		{
			sip_message_free(sip);
			parakeet_session_unlock(session);
			dzlog_warn("Missing 'from'.'tag'");
			return -1;
		}

		if (0 == apr_strnatcmp(tag, sip_message_get_from_tag(session->invite)))
		{
			// 1.如果CSeq相同, Branch相同, From.tag相同, 则认为是同一个INVITE, 该情况不需要处理
			// 2.如果CSeq相同, Branch不同, From.Tag相同, 则路由出现分叉, 需要拒绝第二次的INVITE, 那么482
			// 3.如果CSeq相同, From.Tag不同, 说明UAC端有非法操作. 不理会该请求
			if (sip_message_cseq_get_number(session->invite) == sip_message_cseq_get_number(sip))
			{
				// branch是否一致.
				const char* branch1 = sip_message_get_topvia_branch(sip);
				const char* branch2 = sip_message_get_topvia_branch(session->invite);
				if (NULL != branch1 && NULL != branch2 && 0 != apr_strnatcmp(branch1, branch2))
				{
					//siproxy_send_response(sip, addr, SIP_LOOP_DETECTED, NULL);
				}
			}
			else
			{
				// reINVITE.
				on_parakeet_reinvite(session, sip, d);
			}
		}
		else 
		{
			const char* str = sip_message_get_to_tag(session->invite);
			if (NULL == str || 0 != apr_strnatcmp(tag,str) )
			{
				// tag不一致, 但call-id一致. 有问题, 不处理.
				sip_message_free(sip);
				parakeet_session_unlock(session);
				dzlog_warn("Match 'Call-ID', but no match 'To'.'Tag'");
				return -1;
			}

			// UAS端刷新INVITE请求
			on_parakeet_reinvite(session, sip, d);
		}
		parakeet_session_unlock(session);
		sip_message_free(sip);
		return 0;
	}


	// 如果有To.tag, 
	if (sip_message_get_to_tag(sip))
	{
		// 不存在的呼叫.
		//siproxy_send_response(sip, addr, SIP_CALL_TRANSACTION_DOES_NOT_EXIST, 0);
		sip_message_free(sip);
		parakeet_session_unlock(session);
		return -1;
	}

	// 新的呼入.
	assert(NULL==session);
	
	// 此处并未检查Require和Proxy-Require头域
	// 我们直接透传Require头域即可.
	// 对于Proxy-Require应禁止出现.

	// 另外本处未检查Contact字段

	// 获取主叫
	caller = sip_message_get_from_username(sip);
	// 获取被叫, 被叫来自To来时RequestLine?
	callee = sip_message_get_to_username(sip);

	// 如果主叫/被叫之一是空的, 则拒绝
	if (NULL == caller || NULL == callee ||
		'\0' == *caller || '\0' == *callee)
	{
		// 没有主叫是不行的.

		dzlog_error("incoming: lack of calling!");
		sip_message_free(sip);
		return -1;
	}

    // 创建会话.
	apr_pool_create(&pool, 0);
	session = apr_pcalloc(pool, sizeof(parakeet_session_t));
	session->pool = pool;
	session->callid = apr_pstrdup(pool, callid);
	if(d == PKT_DIRECT_INCOMING)
	{
	    session->dir = DIR_TYPE_INCOMING;
		session->status = STATUS_IN_INVITE;
	}else {
        session->dir = DIR_TYPE_OUTGOING;
		session->status = STATUS_OUT_INVITE;
	}

	// 锁
	apr_thread_mutex_create(&session->mutex, APR_THREAD_MUTEX_DEFAULT, pool);
	apr_thread_mutex_lock(session->mutex);

	// 会话是否已经存在.
	// 由于多线程, 可能会同时收到两个一样的INVITE请求.
	// 处理上需要互斥开.
	apr_thread_rwlock_wrlock(session_globals->session_lock);
	if (NULL == apr_hash_get(session_globals->sessions, session->callid, APR_HASH_KEY_STRING))
	{
		// 不存在, 则添加, 且可以呼叫.
		apr_hash_set(session_globals->sessions, session->callid, APR_HASH_KEY_STRING, session);
		rv = 0;
	}
	apr_thread_rwlock_unlock(session_globals->session_lock);

	if (0 != rv)
	{
		apr_thread_mutex_unlock(session->mutex);
		apr_thread_mutex_destroy(session->mutex);
		apr_pool_destroy(session->pool);

		sip_message_free(sip);
		return -1;
	}

	
	session->from_username = apr_pstrdup(pool, caller);
	session->to_username = apr_pstrdup(pool, callee);
	
	///////////////////////////////////////////////////////////////////////

	session->invite = sip;
	session->call_timeout = 1000 * (parakeet_get_config()->call_timeout); // 毫秒
	session->seq_receiver = sip_message_cseq_get_number(sip);
	session->seq_sender = 1;// session->seq_receiver;  BYE,INFO,INVITE 消息从1递增.  ACK,CANCEL保持与 INVITE 一直.

	// 会话计数
	session->ref = apr_atomic_inc32(&session_globals->next_session_id);

	// 记录开始时间
	time(&session->invite_time);

	assert(0 == session->lastsip);

	if(d == PKT_DIRECT_INCOMING)
	{
		// 日志输出.
		dzlog_info("[%s][%u] recv INVITE, gateway:%d, caller:%s, callee:%s",
			session->callid,
			session->ref,
			session->gateway_id,
			session->from_username,
			session->to_username);
	}else {
		// 日志输出.
		dzlog_info("[%s][%u] send INVITE, gateway:%d, caller:%s, callee:%s",
			session->callid,
			session->ref,
			session->gateway_id,
			session->from_username,
			session->to_username);
	}

	parakeet_session_unlock(session);

    return err;
}

parakeet_errcode_t  on_parakeet_reinvite(parakeet_session_t * session, sip_message_t * sip, packet_direction_t d)
{
	// 收到re-INVITE的处理.

	if(d == PKT_DIRECT_INCOMING)
	{
		parakeet_session_set_status(session, STATUS_IN_INVITE);
		dzlog_info("[%s][%u] recv INVITE, [STANDBY] to [INVITE]!", session->callid, session->ref);
	}else {
        parakeet_session_set_status(session, STATUS_OUT_INVITE);
		dzlog_info("[%s][%u] send INVITE, [STANDBY] to [INVITE]!", session->callid, session->ref);
	}
	
	return 0;
}

parakeet_errcode_t on_parakeet_ack(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;

	parakeet_session_t * session;

	session = parakeet_session_locate(sip_message_get_call_id(sip));
	if (NULL == session)
	{
		return PARAKEET_STATUS_NOT_EXIST;
	}

	switch (session->status)
	{
	case STATUS_IN_REFUSE:
		// 呼入拒绝
		dzlog_info("[%s][%u] recv ACK, [REFUSE] to [STANDBY]!", session->callid, session->ref);
		parakeet_session_set_status(session, STATUS_STANDBY);
		break;

	case STATUS_IN_ANSWER:
		// 呼入应答
		dzlog_info("[%s][%u] recv ACK, [ANSWER] to [TALKING]!", session->callid, session->ref);
		parakeet_session_set_status(session, STATUS_IN_TALKING);
		break;

	case STATUS_IN_CANCEL:
		// 呼入后, 对方取消呼叫, 发送 200&487, 等待ACK
		dzlog_info("[%s][%u] recv ACK, [CANCEL] to [DESTROY]!", session->callid, session->ref);
		parakeet_session_set_status(session, STATUS_DESTROY);
		assert(session->hangup_time > 0);
		break;

	case STATUS_IN_TX_BYE:
		// 需要继续发送BYE.
		break;

	case STATUS_IN_TALKING:
		break;

	case STATUS_OUT_REFUSE:
		// 呼出拒绝
		dzlog_info("[%s][%u] send ACK, [REFUSE] to [STANDBY]!", session->callid, session->ref);
		parakeet_session_set_status(session, STATUS_STANDBY);
		break;

	case STATUS_OUT_ANSWER:
		//呼出应答
		dzlog_info("[%s][%u] send ACK, [ANSWER] to [TALKING]!", session->callid, session->ref);
		parakeet_session_set_status(session, STATUS_OUT_TALKING);
		// 通话中.
		break;

	case STATUS_OUT_CANCEL:
		// 发送CANCEL, 接收200 OK, 接收487, 发送ACK.
		assert(0);
		break;

	case STATUS_DESTROY:
		break;

	default:
		dzlog_debug("[%s][%u] recv ACK, status:%u", session->callid, session->ref, session->status);
		break;
	}

	parakeet_session_unlock(session);

	return err;
}


parakeet_errcode_t on_parakeet_bye(sip_message_t* sip, packet_direction_t d)
{
	// BYE消息挂机.
	parakeet_errcode_t err = PARAKEET_STATUS_OK;
	parakeet_session_t * session;

	session = parakeet_session_locate(sip_message_get_call_id(sip));
	if (NULL == session)
	{
		return PARAKEET_STATUS_NOT_EXIST;
	}
	
	switch (session->status)
	{
		case STATUS_IN_TALKING:
			
			time(&session->hangup_time);
			session->hangup_cause = REASON_USER_BYE;

	        if(d == PKT_DIRECT_INCOMING)
			{
			    dzlog_info("[%s][%u] recv BYE, [TALKING] to [BYE]", session->callid, session->ref);
				parakeet_session_set_status(session, STATUS_IN_RX_BYE);
		    }
			else {
				dzlog_info("[%s][%u] send BYE, [TALKING] to [BYE]", session->callid, session->ref);
				parakeet_session_set_status(session, STATUS_IN_TX_BYE);
			}
			break;

		case STATUS_OUT_TALKING:
			// 呼出通话.
		    time(&session->hangup_time);
		    session->hangup_cause = REASON_USER_BYE;

			if(d == PKT_DIRECT_INCOMING)
			{
			    dzlog_info("[%s][%u] recv BYE, [TALKING] to [BYE]", session->callid, session->ref);
				parakeet_session_set_status(session, STATUS_OUT_RX_BYE);
		    }
			else {
				dzlog_info("[%s][%u] send BYE, [TALKING] to [BYE]", session->callid, session->ref);
				parakeet_session_set_status(session, STATUS_OUT_TX_BYE);
			}
			break;

		case STATUS_IN_RX_BYE:
		case STATUS_OUT_RX_BYE:
			break;

		default:
			break;
	}
	parakeet_session_unlock(session);

	return err;
}


parakeet_errcode_t on_parakeet_cancel(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_register(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}


parakeet_errcode_t on_parakeet_options(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_info(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_unknown(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_trying(sip_message_t* sip)
{
	parakeet_session_t * session;
	parakeet_errcode_t err = PARAKEET_STATUS_OK;

	TRACE("==== TRYING ==== Locate[%s]", sip_message_get_call_id(sip));
	session = parakeet_session_locate(sip_message_get_call_id(sip));
	if (session == NULL)
	{
	    return err;
	}

	switch(session->status)
	{
	   case STATUS_OUT_INVITE:
	       parakeet_session_set_status(session, STATUS_OUT_TRYING);
		   dzlog_info("[%s][%u] recv TRYING, [INVITE] to [TRYING]", session->callid, session->ref);
	       break;
	   case STATUS_IN_INVITE:
	       parakeet_session_set_status(session, STATUS_IN_TRYING);
		   dzlog_info("[%s][%u] send TRYING, [INVITE] to [TRYING]", session->callid, session->ref);
	       break;
	   case STATUS_OUT_TRYING:
	       dzlog_info("[%s][%u] recv TRYING", session->callid, session->ref);
	       break;
	   case STATUS_IN_TRYING:
	       dzlog_info("[%s][%u] send TRYING", session->callid, session->ref);
	       break;
	   default:
	   	   dzlog_error("[%s][%u] error status [%d]", session->callid, session->ref, session->status);
	}

	parakeet_session_unlock(session);

	TRACE("==== TRYING ==== FINISHED [%s]", session->callid);
	
	return err;
}


parakeet_errcode_t on_parakeet_ringing(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;	

	parakeet_session_t * session;
	session = parakeet_session_locate(sip_message_get_call_id(sip));
	assert(session);
	if (0 == session) return -1;

		// 修改状态.
	if (STATUS_OUT_INVITE == session->status || STATUS_OUT_TRYING == session->status )
	{
		parakeet_session_set_status(session, STATUS_OUT_RINGING);
		time(&session->ring_time);
		dzlog_info("[%s][%u] recv RINGING", session->callid, session->ref);
	}else if(STATUS_IN_INVITE == session->status || STATUS_IN_TRYING == session->status )
	{
		parakeet_session_set_status(session, STATUS_IN_RINGING);
		time(&session->ring_time);
		dzlog_info("[%s][%u] send RINGING", session->callid, session->ref);
	}
	parakeet_session_unlock(session);
	
	return err;
}


parakeet_errcode_t on_parakeet_answer(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;	
	parakeet_session_t * session;
	sdp_message_t * invite_sdp;
	sdp_message_t * answer_sdp;
	sdp_media_t * invite_m;
	sdp_media_t * answer_m;
	apr_port_t caller_port;
	apr_port_t callee_port;
	enum session_direction_t direct;	///< 呼叫方向
	uint8_t pt = 0;
	const char * callid;

	session = parakeet_session_locate(sip_message_get_call_id(sip));
	if (0 == session)
	{
		// 不存在的呼叫.
		return PARAKEET_STATUS_NOT_EXIST;
	}

    //修改状态
	// 外呼 被叫应答 .
	if (STATUS_OUT_INVITE == session->status ||
		STATUS_OUT_TRYING == session->status ||
		STATUS_OUT_RINGING == session->status )
	{
	    dzlog_info("[%s][%u] recv OK(INVITE), status: ANSWER", session->callid, session->ref);
		parakeet_session_set_status(session, STATUS_OUT_ANSWER);
		time(&session->answer_time);
	
	}
	//呼入 被叫应答
	else if(STATUS_IN_INVITE == session->status ||
		    STATUS_IN_TRYING == session->status ||
		    STATUS_IN_RINGING == session->status )
	{
	    dzlog_info("[%s][%u] send OK(INVITE), status: ANSWER", session->callid, session->ref);
		parakeet_session_set_status(session, STATUS_IN_ANSWER);
		time(&session->answer_time);
	}

    //解析主叫SDP消息
 
    sdp_message_init(&invite_sdp);
    sdp_message_parse(invite_sdp, sip_message_get_body(session->invite));
	direct = session->dir;

    sdp_message_init(&answer_sdp);
    sdp_message_parse(answer_sdp, sip_message_get_body(sip));

    callid = sip_message_get_call_id(sip);
	
    //SDP情报
	invite_m = (sdp_media_t*)invite_sdp->m_medias.node->element;
	answer_m = (sdp_media_t*)answer_sdp->m_medias.node->element;

	caller_port = (apr_port_t)apr_atoi64(invite_m->m_port);
	callee_port = (apr_port_t)apr_atoi64(answer_m->m_port);
    pt = (uint8_t)apr_atoi64(answer_m->m_payloads.node->element);
	
    //本地rtp端口
    if(direct == DIR_TYPE_INCOMING)
    {
       //呼入时  等于被叫的端口
       session->local_rtp_port = callee_port;
    }else {
       //呼出时等于主叫的端口
       session->local_rtp_port = caller_port;
	}
    //取得情报后释放锁
	parakeet_session_unlock(session);

    //临时处理     没有做参数检查
	err = parakeet_stream_create(callid, direct, caller_port, callee_port, pt);

    dzlog_info("[%s][%u] on_parakeet_answer caller:%s %s", session->callid, session->ref, invite_m->m_media, invite_m->m_port);
	dzlog_info("[%s][%u] on_parakeet_answer callee:%s %s", session->callid, session->ref, answer_m->m_media, answer_m->m_port);

    return err;
}

parakeet_errcode_t on_parakeet_info_ok(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_bye_ok(sip_message_t* sip)
{
	// 挂机完成
	parakeet_session_t * session;
	parakeet_stream_t * stream;
	apr_port_t local_port = 0;

	session = parakeet_session_locate(sip_message_get_call_id(sip));
	if (NULL == session)
	{
		return PARAKEET_STATUS_NOT_EXIST;
	}

	switch (session->status)
	{
	case STATUS_IN_TX_BYE:
	case STATUS_OUT_TX_BYE:
		dzlog_info("[%s][%u] recv OK(BYE)", session->callid, session->ref);
	    // 立即释放会话信息.
	    parakeet_session_set_status(session, STATUS_DESTROY);
	    assert(session->hangup_time > 0);
	    break;
		
	case STATUS_IN_RX_BYE:
	case STATUS_OUT_RX_BYE:
		dzlog_info("[%s][%u] send OK(BYE)", session->callid, session->ref);
	    // 立即释放会话信息.
	    parakeet_session_set_status(session, STATUS_DESTROY);
	    assert(session->hangup_time > 0);
		break;

	case STATUS_DESTROY:
		break;

	default:
		assert(0);
		break;
	}
	
    /**
    * 关闭写媒体流的文件描述符
    * 如果使用buffer 需要检查buffer内数据大小
    */
    local_port = session->local_rtp_port;
	
	parakeet_session_unlock(session);

	stream = parakeet_stream_locate(local_port);
	
    assert(stream);

	parakeet_set_flag(stream, PSSF_STREAM_CLOSE);

	parakeet_stream_unlock(stream);
	
	return 0;
}


parakeet_errcode_t on_parakeet_cancel_ok(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_callfail(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_terminated(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

parakeet_errcode_t on_parakeet_authentication_required(sip_message_t* sip)
{
	parakeet_session_t * session;
	parakeet_errcode_t err = PARAKEET_STATUS_OK;
	 
	session = parakeet_session_locate(sip_message_get_call_id(sip));
	//assert(session);
	if (0 == session) return -1;

	assert(STATUS_OUT_INVITE == session->status || STATUS_OUT_TRYING == session->status ||
	       STATUS_IN_INVITE == session->status || STATUS_IN_TRYING == session->status);

	// 加上鉴权信息再次呼叫.407 Proxy Authentication Required
	
	session->seq_sender = sip_message_cseq_get_number(session->invite);

	// 变更状态.
	if(STATUS_OUT_INVITE == session->status || STATUS_OUT_TRYING == session->status)
	{
	    dzlog_info("[%s][%u] recv 407, [INVITE] to [REFUSE]!", session->callid, session->ref);
	    parakeet_session_set_status(session, STATUS_OUT_REFUSE);
	}else {
	    dzlog_info("[%s][%u] send 407, [INVITE] to [REFUSE]!", session->callid, session->ref);
	    parakeet_session_set_status(session, STATUS_IN_REFUSE);
	}
	
	parakeet_session_unlock(session);

	return err;
}


parakeet_errcode_t on_parakeet_transaction_does_not_exist(sip_message_t* sip)
{
    parakeet_errcode_t err = PARAKEET_STATUS_OK;
	
    return err;
}

void parakeet_cdr_write(parakeet_session_t * session)
{
	// 写话单
	char sql[1024];
	int len;
	int sec = 0;

	assert(session->invite_time > 0);
	assert(session->hangup_time >= session->invite_time);
	assert(parakeet_get_config()->cdr_enable);

	if (STATUS_STANDBY == session->status ||
		NULL == session->invite ||
		NULL == session->from_username ||
		NULL == session->to_username)
	{
		return;
	}

	// FIELDS
	len = sprintf(sql, 
		"INSERT INTO cdr%s (ref,callid,caller,callee,direction,gateway_id,invite_time,", 
		parakeet_mysql_cdr_date());
	if (session->ring_time > 0) len += sprintf(sql + len, "ring_time,");
	if (session->answer_time > 0)
	{
		len += sprintf(sql + len, "answer_time,");
		sec = (int)(session->hangup_time - session->answer_time);
	}
	len += sprintf(sql + len, "hangup_time,talk_second,hangup_cause) VALUES(");

	// VALUE
	len += sprintf(sql + len, "%u,'%s','%s','%s',%d,%d,FROM_UNIXTIME(%ld),",
		session->ref,
		session->callid, session->from_username, session->to_username,
		(DIR_TYPE_INCOMING == session->dir) ? 0 : 1,
		session->gateway_id, (long)session->invite_time);

	if (session->ring_time > 0) len += sprintf(sql + len, "FROM_UNIXTIME(%ld),", (long)session->ring_time);
	if (session->answer_time > 0) len += sprintf(sql + len, "FROM_UNIXTIME(%ld),", (long)session->answer_time);
	len += sprintf(sql + len, "FROM_UNIXTIME(%ld),%d,%d);", (long)session->hangup_time, sec, session->hangup_cause);
	parakeet_mysql_push(sql);
}


DECLARE_TASK_INTERFACE(on_session_timeout_destroy)
{
	// 任意情况的会话最终销毁操作都会进入本函数处理.
	parakeet_session_t * session = (parakeet_session_t *)param;

	apr_thread_rwlock_wrlock(session_globals->session_lock);
	if (APR_SUCCESS != apr_thread_mutex_trylock(session->mutex))
	{
		apr_thread_rwlock_unlock(session_globals->session_lock);
		return NULL;
	}

	assert(session->callid);
	apr_hash_set(session_globals->sessions, session->callid, APR_HASH_KEY_STRING, 0);

	apr_thread_mutex_unlock(session->mutex);

	apr_thread_rwlock_unlock(session_globals->session_lock);

	// 写话单.
	if (parakeet_get_config()->cdr_enable)
	{
		parakeet_cdr_write(session);
	}
	
	dzlog_info("[%s][%u] destroy!", session->callid, session->ref);

	if (session->invite) sip_message_free(session->invite);
	if (session->lastsip) sip_message_free(session->lastsip);
	
	apr_thread_mutex_destroy(session->mutex);
	apr_pool_destroy(session->pool);

	return NULL;
}

int parakeet_session_http_query(struct evbuffer * evb,
	int page, int pageSize,
	int gateway_id, const char * caller, const char * callee,
	int direction, int status)
{
	// 扫描所有会话. 这个操作比较耗时.
	apr_hash_index_t * hi;
	parakeet_session_t * s = 0;

	apr_uint32_t total = 0;
	apr_uint32_t offset = 0;

	// 实际开始位置
	apr_uint32_t start = (page-1) * pageSize;
	// 最大位置.
	apr_uint32_t end = start + pageSize;
	// 呼叫方向.
	enum session_direction_t  dir = DIR_TYPE_ANY;
	// 呼叫状态.
//	enum session_status_t status = STATUS_STANDBY;

	if (1 == direction) dir = DIR_TYPE_INCOMING;
	else if (2 == direction) dir = DIR_TYPE_OUTGOING;

	evbuffer_add_printf(evb, "{\"code\":0,\"data\":{\"page\":%u,\"pageSize\":%u,\"data\":[",
		page, pageSize);

	apr_thread_rwlock_rdlock(session_globals->session_lock);
	for (hi = apr_hash_first(0, session_globals->sessions); hi; hi = apr_hash_next(hi))
	{
		s = apr_hash_this_val(hi);

		apr_thread_mutex_lock(s->mutex);

		do
		{
			if (s->ref == 0)
				break;

			// 比较: 网关
			if (gateway_id > 0 )
			{
				// if (0 != apr_strnatcmp(gateway_name, s->gateway_name))
				if (gateway_id != s->gateway_id)
				{
					// 不符合.
					TRACE("Session.dismatch");
					break;
				}
			}

			// 比较: 主叫号码(模糊匹配)
			if (caller && s->from_username)
			{
				if (NULL == strstr(s->from_username, caller))
				{
					// 不符合
					TRACE("Session.dismatch");
					break;
				}
			}

			// 比较: 被叫号码(模糊匹配)
			if (callee && s->to_username)
			{
				if (NULL == strstr(s->to_username, callee))
				{
					// 不符合
					TRACE("Session.dismatch");
					break;
				}
			}

			// 比较: 呼叫方向
			if (DIR_TYPE_ANY != dir)
			{
				// 方向.
				if (s->dir != dir)
				{
					TRACE("Session.dismatch");
					break;
				}
			}

			// 比较: 会话状态.
			if (STATUS_STANDBY != status)
			{
				if (s->status != status)
				{
					TRACE("Session.dismatch");
					break;
				}
			}

			// 所有条件符合.
			if(offset >= start && offset < end)
			{
				struct tm * ptm = localtime(&s->invite_time);

				if (offset != start) evbuffer_add(evb, ",", 1);

				// 会话信息.

				evbuffer_add_printf(evb,
					"{"
					"\"index\":%u"
					",\"callid\":\"%s\""
					",\"ref\":%u"
					",\"caller\":\"%s\""
					",\"callee\":\"%s\""
					",\"gateway_id\":%d"
					",\"status_code\":%d"
					",\"status_desc\":\"%s\""
					",\"duration\":%u"
					",\"direction\":\"%s\""
					",\"start\":\"%d-%d-%d %02d:%02d:%02d\""
					"}",
					offset,
					s->callid,
					s->ref,
					s->from_username,
					s->to_username,
					s->gateway_id,
					s->status,
					SESSION_STATUS_STRING[s->status],
					s->status_duration,
					(DIR_TYPE_INCOMING == s->dir) ? DIR_STR_INCOMING : DIR_STR_OUTGOING,
					ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
			}
			offset++;
			total++;

			TRACE("Session.Match Success, Offset:%d, Total:%d", offset, total);

		} while (0);

		TRACE("hi=%p", hi);

		apr_thread_mutex_unlock(s->mutex);
	}

	apr_thread_rwlock_unlock(session_globals->session_lock);

	evbuffer_add_printf(evb, "],\"total\":%u}}", total);
	return total;
}



