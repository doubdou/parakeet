#ifndef PARAKEET_CODEC_H
#define PARAKEET_CODEC_H

#include "parakeet_config.h"


apr_size_t parakeet_g711a_decoder_process(uint8_t* data, apr_size_t len, uint8_t* decoded_data, apr_size_t decoded_len);

apr_size_t parakeet_g711u_decoder_process(uint8_t* data, apr_size_t len, uint8_t* decoded_data, apr_size_t decoded_len);


#endif

