#ifndef PARAKEET_TYPES_H
#define PARAKEET_TYPES_H

/* size of the buffer */
#define PARAKEET_BUFFER_SIZE       (1024 * 64)
#define PARAKEET_BUFFER_BLOCKSIZE  (1024 * 512)
#define PARAKEET_BYTES_PER_SAMPLE  (2)	      /* 2 bytes per sample */

#define PARAKEET_RECOMMENDED_BUFFER_SIZE (8192)

#define PARAKEET_SMAX 32767

#define PARAKEET_SMIN -32768


#define PARAKEET_MAX_STACKS 16
#define PARAKEET_THREAD_STACKSIZE 240 * 1024
#define PARAKEET_SYSTEM_THREAD_STACKSIZE 8192 * 1024

typedef uint8_t parakeet_payload_t;
typedef int32_t parakeet_bool_t;

typedef enum {
	PARAKEET_ABC_TYPE_INIT,
	PARAKEET_ABC_TYPE_READ,
	PARAKEET_ABC_TYPE_WRITE,
	PARAKEET_ABC_TYPE_READ_PING,
	PARAKEET_ABC_TYPE_TAP_NATIVE_READ,
	PARAKEET_ABC_TYPE_TAP_NATIVE_WRITE,
	PARAKEET_ABC_TYPE_CLOSE,
} parakeet_abc_type_t;

typedef enum {
	PFF_NONE = 0,
	PFF_CNG = (1 << 0),
	PFF_RAW_RTP = (1 << 1),
	PFF_RTP_HEADER = (1 << 2),
	PFF_PLC = (1 << 3),
	PFF_RFC2833 = (1 << 4),
	PFF_PROXY_PACKET = (1 << 5),
	PFF_DYNAMIC = (1 << 6),
	PFF_ZRTP = (1 << 7),
	PFF_UDPTL_PACKET = (1 << 8),
	PFF_NOT_AUDIO = (1 << 9),
	PFF_RTCP = (1 << 10),
	PFF_MARKER = (1 << 11),
	PFF_WAIT_KEY_FRAME = (1 << 12),
	PFF_RAW_RTP_PARSE_FRAME = (1 << 13),
	PFF_PICTURE_RESET = (1 << 14),
	PFF_SAME_IMAGE = (1 << 15),
	PFF_USE_VIDEO_TIMESTAMP = (1 << 16),
	PFF_ENCODED = (1 << 17),
	PFF_TEXT_LINE_BREAK = (1 << 18),
	PFF_IS_KEYFRAME = (1 << 19),
	PFF_EXTERNAL = (1 << 20)
} parakeet_frame_flag_enum_t;
	
typedef uint32_t parakeet_frame_flag_t;


typedef enum{
    PARAKEET_RECORD_FMT_NATIVE,
    PARAKEET_RECORD_FMT_NORMAL,
    PARAKEET_RECORD_FMT_STEREO
}parakeet_record_fmt_t;

typedef enum {
	PSSF_BOTH = 0,
	PSSF_STREAM_OPEN = (1 << 0),
	PSSF_STREAM_CLOSE = (1 << 1)
} parakeet_stream_state_flag_enum_t;	
	
typedef uint32_t parakeet_stream_state_flag_t;

typedef enum {
	PMBF_BOTH = 0,
	PMBF_READ_STREAM = (1 << 0),
	PMBF_WRITE_STREAM = (1 << 1),
	PMBF_WRITE_REPLACE = (1 << 2),
	PMBF_READ_REPLACE = (1 << 3),
	PMBF_READ_PING = (1 << 4),
	PMBF_STEREO = (1 << 5),
	PMBF_ANSWER_REQ = (1 << 6),
	PMBF_BRIDGE_REQ = (1 << 7),
	PMBF_THREAD_LOCK = (1 << 8),
	PMBF_PRUNE = (1 << 9),
	PMBF_NO_PAUSE = (1 << 10),
	PMBF_STEREO_SWAP = (1 << 11),
	PMBF_LOCK = (1 << 12),
	PMBF_TAP_NATIVE_READ = (1 << 13),
	PMBF_TAP_NATIVE_WRITE = (1 << 14),
	PMBF_ONE_ONLY = (1 << 15),
	PMBF_MASK = (1 << 16),
	PMBF_READ_VIDEO_PING = (1 << 17),
	PMBF_WRITE_VIDEO_PING = (1 << 18),
	PMBF_READ_VIDEO_STREAM = (1 << 19),
	PMBF_WRITE_VIDEO_STREAM = (1 << 20),
	PMBF_VIDEO_PATCH = (1 << 21),
	PMBF_SPY_VIDEO_STREAM = (1 << 22),
	PMBF_SPY_VIDEO_STREAM_BLEG = (1 << 23),
	PMBF_READ_VIDEO_PATCH = (1 << 24),
	PMBF_READ_TEXT_STREAM = (1 << 25)
} parakeet_media_bug_flag_enum_t;	
	
typedef uint32_t parakeet_media_bug_flag_t;

/*!
  \enum parakeet_file_flag_t
  \brief File flags
<pre>
PARAKEET_FILE_FLAG_READ =         (1 <<  0) - Open for read
PARAKEET_FILE_FLAG_WRITE =        (1 <<  1) - Open for write
PARAKEET_FILE_FLAG_FREE_POOL =    (1 <<  2) - Free file handle's pool on destruction
PARAKEET_FILE_DATA_SHORT =        (1 <<  3) - Read data in shorts
PARAKEET_FILE_DATA_INT =          (1 <<  4) - Read data in ints
PARAKEET_FILE_DATA_FLOAT =        (1 <<  5) - Read data in floats
PARAKEET_FILE_DATA_DOUBLE =       (1 <<  6) - Read data in doubles
PARAKEET_FILE_DATA_RAW =          (1 <<  7) - Read data as is
PARAKEET_FILE_PAUSE =             (1 <<  8) - Pause
PARAKEET_FILE_NATIVE =            (1 <<  9) - File is in native format (no transcoding)
PARAKEET_FILE_SEEK = 				(1 << 10) - File has done a seek
PARAKEET_FILE_OPEN =              (1 << 11) - File is open
</pre>
 */
typedef enum {
	PARAKEET_FILE_FLAG_READ = (1 << 0),
	PARAKEET_FILE_FLAG_WRITE = (1 << 1),
	PARAKEET_FILE_FLAG_FREE_POOL = (1 << 2),
	PARAKEET_FILE_DATA_SHORT = (1 << 3),
	PARAKEET_FILE_DATA_INT = (1 << 4),
	PARAKEET_FILE_DATA_FLOAT = (1 << 5),
	PARAKEET_FILE_DATA_DOUBLE = (1 << 6),
	PARAKEET_FILE_DATA_RAW = (1 << 7),
	PARAKEET_FILE_PAUSE = (1 << 8),
	PARAKEET_FILE_NATIVE = (1 << 9),
	PARAKEET_FILE_SEEK = (1 << 10),
	PARAKEET_FILE_OPEN = (1 << 11),
	PARAKEET_FILE_CALLBACK = (1 << 12),
	PARAKEET_FILE_DONE = (1 << 13),
	PARAKEET_FILE_BUFFER_DONE = (1 << 14),
	PARAKEET_FILE_WRITE_APPEND = (1 << 15),
	PARAKEET_FILE_WRITE_OVER = (1 << 16),
	PARAKEET_FILE_NOMUX = (1 << 17),
	PARAKEET_FILE_BREAK_ON_CHANGE = (1 << 18),
	PARAKEET_FILE_FLAG_VIDEO = (1 << 19),
	PARAKEET_FILE_FLAG_VIDEO_EOF = (1 << 20)
} parakeet_file_flag_enum_t;
typedef uint32_t parakeet_file_flag_t;



#endif

