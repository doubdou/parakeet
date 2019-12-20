#ifndef PARAKEET_SESSION_H
#define PARAKEET_SESSION_H

parakeet_errcode_t parakeet_session_init(apr_pool_t * pool);

void * APR_THREAD_FUNC parakeet_session_state_machine(apr_thread_t * thread, void * param);


#endif

