#ifndef PARAKEET_COM_H_
#define PARAKEET_COM_H_
#include <ctype.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** payload type */
/*
* RTP协议对72~76的负载做了预留, 为避免与RTCP冲突。
* VoIP音频编码G系列, 因为常用的就那么几种，所以目前支持部分编码格式
* 另外,除了明确指定PT值的负载类型，还有些负载类型由于诞生的较晚，没有具体的PT值，只能使用动态(dynamic)PT值，即96到127
* ---------------------------------
* | Payload  | encode name		  |
* ---------------------------------
* | 0		 | G711U			  |
* ---------------------------------
* | 8		 | G711A			  |
* ---------------------------------
* | 9		 | G722 			  |
* ---------------------------------
* | 18		 | G729 			  |
* ---------------------------------
* | 72-76	 | 避免与RTCP冲突预留	|
* ---------------------------------
* | 96-127	 | dynamic            |
* --------------------------------- 
* | 101 	 | telephone event	  |
* --------------------------------- 
*/
#define PT_PCMU      0
#define PT_G723      4
#define PT_PCMA      8
#define PT_G722      9
#define PT_L16_2     10
#define PT_L16_1     11        
#define PT_G729		 18
#define PT_RFC2833   101

#define ETH_HDR_LENGTH   	    sizeof(eth_header_t)
#define ETH_8021Q_TAG_LENGTH    sizeof(eth_8021q_tag_t)
#define IP_HDR_LENGTH  		    sizeof(ip_header_t)
#define TCP_HDR_LENGTH          sizeof(tcp_header_t)
#define UDP_HDR_LENGTH 		    sizeof(udp_header_t)
#define RTP_HDR_LENGTH 		    sizeof(rtp_header_t)


#define ETH_TYPE_IPV4           0x0800
#define ETH_TYPE_802_1Q         0x8100

#define IP_PROTOCOL_NUM_TCP 	0x06
#define IP_PROTOCOL_NUM_UDP     0x11

#define RTP_HEADER_VER_NUM      0X02

#define RTCP_PACKET_TYPE_SR		200
#define RTCP_PACKET_TYPE_RR		201
#define RTCP_PACKET_TYPE_SDES	202
#define RTCP_PACKET_TYPE_BYE	203
#define RTCP_PACKET_TYPE_APP    204

typedef struct eth_header_s
{
    uint8_t 	dst_mac[6];
    uint8_t 	src_mac[6];
    uint16_t 	eth_type;
}eth_header_t;

typedef struct eth_8021q_tag_s{
	uint16_t     priority:3;
	uint16_t     dei:1;
	uint16_t     vlan_id:12;
	uint16_t     type;
}eth_8021q_tag_t;

typedef struct ip_header_s
{
    int 		version:4;
    int 		header_len:4;
    uint8_t 	tos:8;
    int 	 	total_len:16;
    int 		ident:16;
    int 		flags:16;
    uint8_t		ttl:8;
    uint8_t 	protocol:8;
    int 	 	checksum:16;
    uint8_t 	sourceIP[4];
    uint8_t 	destIP[4];
}ip_header_t;


typedef struct tcp_header_s
{
    uint16_t 	sport;
    uint16_t 	dport;
    uint32_t 	seq;
    uint32_t	 ack;
    uint8_t 	head_len;
    uint8_t 	flags;
    uint16_t 	wind_size;
    uint16_t 	check_sum;
    uint16_t  	urg_ptr;
}tcp_header_t;


typedef struct udp_header_s
{
    uint16_t 	sport;
    uint16_t 	dport;
    uint16_t 	tot_len;
    uint16_t	check_sum;
}udp_header_t;


typedef struct rtp_header_s
{
 	uint16_t csrc_count:4;
 	uint16_t extension:1;
 	uint16_t padding:1;
 	uint16_t version:2;
 	uint16_t payloadtype:7; 
 	uint16_t marker:1; 

 	uint16_t seq;
 	uint32_t timestamp;
 	uint32_t ssrc;
}rtp_header_t;


typedef struct rtcp_header_s
{
	uint16_t csrc_count:5;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t payloadtype:8; 
	uint16_t length; 
 
	uint32_t ssrc;
}rtcp_header_t;


typedef struct rtppacket_s{
	eth_header_t*  	eth_hdr;
	ip_header_t*   	ip_hdr;
	udp_header_t*  	udp_hdr;
	rtp_header_t*  	rtp_hdr;
	void*          	media_data;
}rtppacket_t;

/** for g711 decoder */
#define         SIGN_BIT        (0x80)      /* Sign bit for a A-law byte. */
#define         QUANT_MASK      (0xf)       /* Quantization field mask. */
#define         NSEGS           (8)         /* Number of A-law segments. */
#define         SEG_SHIFT       (4)         /* Left shift for segment number. */
#define         SEG_MASK        (0x70)      /* Segment field mask. */
#define         BIAS            (0x84)      /* Bias for linear code. */
#define			CLIP            (8159)
 
#define			G711_A_LAW		(0)
#define			G711_U_LAW		(1)
#define			G711_DATA_LEN	(160)

#if 0
short seg_aend[8] = {
	0x1F, 0x3F, 0x7F, 0xFF,
	0x1FF, 0x3FF, 0x7FF, 0xFFF
};
 
short seg_uend[8] = {
	0x3F, 0x7F, 0xFF, 0x1FF,
	0x3FF, 0x7FF, 0xFFF, 0x1FFF
};
	

unsigned char _u2a[128] = {
	/* u- to A-law conversions */
	1,1,2,2,3,3,4,4,
	5,5,6,6,7,7,8,8,
	9,10,11,12,13,14,15,16,
	17,18,19,20,21,22,23,24,
	25,27,29,31,33,34,35,36,
	37,38,39,40,41,42,43,44,
	46,48,49,50,51,52,53,54,
	55,56,57,58,59,60,61,62,
	64,65,66,67,68,69,70,71,
	72,73,74,75,76,77,78,79,
	81,82,83,84,85,86,87,88, 
	89,90,91,92,93,94,95,96,
	97,98,99,100,101,102,103,104,
	105,106,107,108,109,110,111,112,
	113,114,115,116,117,118,119,120,
	121,122,123,124,125,126,127,128
};
 
unsigned char _a2u[128] = {
	/* A- to u-law conversions */
	1,3,5,7,9,11,13,15,
	16,17,18,19,20,21,22,23,
	24,25,26,27,28,29,30,31,
	32,32,33,33,34,34,35,35,
	36,37,38,39,40,41,42,43,
	44,45,46,47,48,48,49,49,
	50,51,52,53,54,55,56,57,
	58,59,60,61,62,63,64,64,
	65,66,67,68,69,70,71,72,
	73,74,75,76,77,78,79,79,
	80,81,82,83,84,85,86,87,
	88,89,90,91,92,93,94,95,
	96,97,98,99,100,101,102,103,
	104,105,106,107,108,109,110,111,
	112,113,114,115,116,117,118,119,
	120,121,122,123,124,125,126,127
};

typedef struct res_bitmap_s{
    uint32_t       bitmap;
}res_bitmap_t; 

res_bitmap_t res_bitmap_cat[32]= {
{0x00000001},{0x00000002},{0x00000004},{0x00000008},
{0x00000010},{0x00000020},{0x00000040},{0x00000080},
{0x00000100},{0x00000200},{0x00000400},{0x00000800},
{0x00001000},{0x00002000},{0x00004000},{0x00008000},
{0x00010000},{0x00020000},{0x00040000},{0x00080000},
{0x00100000},{0x00200000},{0x00400000},{0x00800000},
{0x01000000},{0x02000000},{0x04000000},{0x08000000},
{0x10000000},{0x20000000},{0x40000000},{0x80000000},
};

res_bitmap_t res_bitmap_rel[32]= {
{0xfffffffe},{0xfffffffd},{0xfffffffb},{0xfffffff7},
{0xffffffef},{0xffffffdf},{0xffffffbf},{0xffffff7f},
{0xfffffeff},{0xfffffdff},{0xfffffbff},{0xfffff7ff},
{0xffffefff},{0xffffdfff},{0xffffbfff},{0xffff7fff},
{0xfffeffff},{0xfffdffff},{0xfffbffff},{0xfff7ffff},
{0xffefffff},{0xffdfffff},{0xffbfffff},{0xff7fffff},
{0xfeffffff},{0xfdffffff},{0xfbffffff},{0xf7ffffff},
{0xefffffff},{0xdfffffff},{0xbfffffff},{0x7fffffff},
};

#endif

#ifdef __cplusplus
}
#endif

#endif


