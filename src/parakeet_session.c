#include "parakeet_config.h"
#include "parakeet_session.h"

parakeet_errcode_t parakeet_session_init(apr_pool_t * pool)
{
    parakeet_errcode_t errcode = PARAKEET_OK;
	
    return errcode;
}

void * APR_THREAD_FUNC parakeet_session_state_machine(apr_thread_t * thread, void * param)
{

	dzlog_notice("StateMachine: thread[%p] running...", thread);


	dzlog_notice("StateMachine: thread[%p] exit...", thread);
    return NULL;
}


