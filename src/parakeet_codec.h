#ifndef PARAKEET_CODEC_H
#define PARAKEET_CODEC_H

#include "parakeet_config.h"
#include "parakeet_types.h"
#include "parakeet_utils.h"




/** Codec virtual table declaration */
typedef struct parakeet_codec_vtable_t parakeet_codec_vtable_t;
/** Codec declaration*/
typedef struct parakeet_codec_t parakeet_codec_t;

/** Codec */
struct parakeet_codec_t {
	/** Codec manipulators (encode, decode, dissect) */
	const parakeet_codec_vtable_t     *vtable;
	/** Codec attributes (capabilities) */
	const parakeet_codec_attribs_t    *attribs;
	/** Optional static codec descriptor (pt < 96) */
	const parakeet_codec_descriptor_t *static_descriptor;
};

/** Table of codec virtual methods */
struct parakeet_codec_vtable_t {
	/** Virtual open method */
	parakeet_bool_t (*open)(parakeet_codec_t *codec);
	/** Virtual close method */
	parakeet_bool_t (*close)(parakeet_codec_t *codec);

	/** Virtual encode method */
	parakeet_bool_t (*encode)(parakeet_codec_t *codec, const parakeet_codec_frame_t *frame_in, parakeet_codec_frame_t *frame_out);
	/** Virtual decode method */
	parakeet_bool_t (*decode)(parakeet_codec_t *codec, const parakeet_codec_frame_t *frame_in, parakeet_codec_frame_t *frame_out);

	/** Virtual dissect method */
	parakeet_bool_t (*dissect)(parakeet_codec_t *codec, void **buffer, apr_size_t *size, parakeet_codec_frame_t *frame);

	/** Virtual initialize method */
	parakeet_bool_t (*initialize)(parakeet_codec_t *codec, parakeet_codec_frame_t *frame_out);
};










/*!
  \enum parakeet_codec_type_t
  \brief Codec types
<pre>
PARAKEET_CODEC_TYPE_AUDIO - Audio Codec
PARAKEET_CODEC_TYPE_VIDEO - Video Codec
PARAKEET_CODEC_TYPE_T38   - T38 Codec
PARAKEET_CODEC_TYPE_APP   - Application Codec
</pre>
 */
typedef enum {
	PARAKEET_CODEC_TYPE_AUDIO,
	PARAKEET_CODEC_TYPE_VIDEO,
	PARAKEET_CODEC_TYPE_T38,
	PARAKEET_CODEC_TYPE_APP
} parakeet_codec_type_t;

typedef union  parakeet_codec_settings parakeet_codec_settings_t;

struct parakeet_audio_codec_settings {
	int unused;
};

struct parakeet_video_codec_settings {
	uint32_t bandwidth;
	int32_t width;
	int32_t height;
	uint8_t try_hardware_encoder;
	uint8_t fps;
};

typedef union  parakeet_codec_settings parakeet_codec_settings_t;

union parakeet_codec_settings {
	struct parakeet_audio_codec_settings audio;
	struct parakeet_video_codec_settings video;
};


/*!
  \enum switch_codec_flag_t
  \brief Codec related flags
<pre>
PARAKEET_CODEC_FLAG_ENCODE =			(1 <<  0) - Codec can encode
PARAKEET_CODEC_FLAG_DECODE =			(1 <<  1) - Codec can decode
PARAKEET_CODEC_FLAG_SILENCE_START =	(1 <<  2) - Start period of silence
PARAKEET_CODEC_FLAG_SILENCE_STOP =	(1 <<  3) - End period of silence
PARAKEET_CODEC_FLAG_SILENCE =			(1 <<  4) - Silence
PARAKEET_CODEC_FLAG_FREE_POOL =		(1 <<  5) - Free codec's pool on destruction
PARAKEET_CODEC_FLAG_AAL2 =			(1 <<  6) - USE AAL2 Bitpacking
PARAKEET_CODEC_FLAG_PASSTHROUGH =		(1 <<  7) - Passthrough only
</pre>
*/
typedef enum {
	PARAKEET_CODEC_FLAG_ENCODE = (1 << 0),
	PARAKEET_CODEC_FLAG_DECODE = (1 << 1),
	PARAKEET_CODEC_FLAG_SILENCE_START = (1 << 2),
	PARAKEET_CODEC_FLAG_SILENCE_STOP = (1 << 3),
	PARAKEET_CODEC_FLAG_SILENCE = (1 << 4),
	PARAKEET_CODEC_FLAG_FREE_POOL = (1 << 5),
	PARAKEET_CODEC_FLAG_AAL2 = (1 << 6),
	PARAKEET_CODEC_FLAG_PASSTHROUGH = (1 << 7),
	PARAKEET_CODEC_FLAG_READY = (1 << 8),
	PARAKEET_CODEC_FLAG_HAS_ADJ_BITRATE = (1 << 14),
	PARAKEET_CODEC_FLAG_HAS_PLC = (1 << 15),
	PARAKEET_CODEC_FLAG_VIDEO_PATCHING = (1 << 16)
} parakeet_codec_flag_enum_t;
typedef uint32_t parakeet_codec_flag_t;

typedef struct parakeet_codec_fmtp parakeet_codec_fmtp_t;

/*! an abstract handle of a fmtp parsed by codec */
struct parakeet_codec_fmtp {
	/*! actual samples transferred per second for those who are not moron g722 RFC writers */
	uint32_t actual_samples_per_second;
	/*! bits transferred per second */
	int bits_per_second;
	/*! number of microseconds of media in one packet (ptime * 1000) */
	int microseconds_per_packet;
	/*! stereo  */
	int stereo;
	/*! private data for the codec module to store handle specific info */
	void *private_info;

};

typedef enum {
	PCCC_VIDEO_GEN_KEYFRAME = 0,
	PCCC_VIDEO_BANDWIDTH,
	PCCC_VIDEO_RESET,
	PCCC_AUDIO_PACKET_LOSS,
	PCCC_AUDIO_ADJUST_BITRATE,
	PCCC_DEBUG,
	PCCC_CODEC_SPECIFIC
} parakeet_codec_control_command_t;

typedef enum {
	PCCT_NONE = 0,
	PCCT_STRING,
	PCCT_INT,
} parakeet_codec_control_type_t;


typedef struct parakeet_codec_implementation parakeet_codec_implementation_t;

typedef struct parakeet_codec parakeet_codec_t;

typedef parakeet_errcode_t (*parakeet_core_codec_decode_func_t) (parakeet_codec_t *codec,
															parakeet_codec_t *other_codec,
															void *encoded_data,
															uint32_t encoded_data_len,
															uint32_t encoded_rate,
															void *decoded_data, uint32_t *decoded_data_len, uint32_t *decoded_rate, unsigned int *flag);

typedef parakeet_errcode_t (*parakeet_core_codec_control_func_t) (parakeet_codec_t *codec,
																   parakeet_codec_control_command_t cmd,
																   parakeet_codec_control_type_t ctype,
																   void *cmd_data,
																   parakeet_codec_control_type_t atype,
																   void *cmd_arg,
																   parakeet_codec_control_type_t *rtype,
																   void **ret_data);

typedef parakeet_errcode_t (*parakeet_core_codec_init_func_t) (parakeet_codec_t *, parakeet_codec_flag_t, const parakeet_codec_settings_t *codec_settings);
typedef parakeet_errcode_t (*parakeet_core_codec_fmtp_parse_func_t) (const char *fmtp, parakeet_codec_fmtp_t *codec_fmtp);
typedef parakeet_errcode_t (*parakeet_core_codec_destroy_func_t) (parakeet_codec_t *);


/*! \brief A table of settings and callbacks that define a paticular implementation of a codec */
struct parakeet_codec_implementation {
	/*! enumeration defining the type of the codec */
	parakeet_codec_type_t codec_type;
	/*! the IANA code number */
	parakeet_payload_t ianacode;
	/*! the IANA code name */
	char *iananame;
	/*! default fmtp to send (can be overridden by the init function) */
	char *fmtp;
	/*! samples transferred per second */
	uint32_t samples_per_second;
	/*! actual samples transferred per second for those who are not moron g722 RFC writers */
	uint32_t actual_samples_per_second;
	/*! bits transferred per second */
	int bits_per_second;
	/*! number of microseconds of media in one packet (ptime * 1000) */
	int microseconds_per_packet;
	/*! number of samples in one packet */
	uint32_t samples_per_packet;
	/*! number of bytes one packet will decompress to */
	uint32_t decoded_bytes_per_packet;
	/*! number of encoded bytes in the RTP payload */
	uint32_t encoded_bytes_per_packet;
	/*! number of channels represented */
	uint8_t number_of_channels;
	/*! number of codec frames packetized into one packet */
	int codec_frames_per_packet;
	/*! function to initialize a codec handle using this implementation */
	parakeet_core_codec_init_func_t init;
	/*! function to decode encoded data into raw data */
	parakeet_core_codec_decode_func_t decode;
	/*! function to send control messages to the codec */
	parakeet_core_codec_control_func_t codec_control;
	/*! deinitalize a codec handle using this implementation */
	parakeet_core_codec_destroy_func_t destroy;
	uint32_t codec_id;
	uint32_t impl_id;
	char *modname;
	struct parakeet_codec_implementation *next;
};

/*! an abstract handle to a codec module */
struct parakeet_codec {
	/*! the specific implementation of the above codec */
	const parakeet_codec_implementation_t *implementation;
	/*! fmtp line from remote sdp */
	char *fmtp_in;
	/*! fmtp line for local sdp */
	char *fmtp_out;
	/*! flags to modify behaviour */
	uint32_t flags;
	/*! the handle's memory pool */
	apr_pool_t *memory_pool;
	/*! private data for the codec module to store handle specific info */
	void *private_info;
	parakeet_payload_t agreed_pt;
	apr_thread_mutex_t *mutex;
	struct parakeet_codec *next;
};


apr_size_t parakeet_g711a_decoder_process(uint8_t* encoded_data, apr_size_t len, uint8_t* decoded_data);

apr_size_t parakeet_g711u_decoder_process(uint8_t* encoded_data, apr_size_t len, uint8_t* decoded_data);

parakeet_codec_implementation_t* parakeet_codec_implementation_create(apr_pool_t * pool);

parakeet_errcode_t parakeet_core_codec_decode(parakeet_codec_t *codec,parakeet_codec_t *other_codec,
													 void *encoded_data, uint32_t encoded_data_len, uint32_t encoded_rate,
													 void *decoded_data, uint32_t *decoded_data_len, uint32_t *decoded_rate, unsigned int *flag);



#endif

