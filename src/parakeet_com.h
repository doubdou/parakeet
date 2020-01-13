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
	eth_header_t    eth_hdr;
	ip_header_t     ip_hdr;
	udp_header_t    udp_hdr;
	rtp_header_t    rtp_hdr;
	void*          	body;
}rtppacket_t;

typedef struct rtp_msg_s{
	rtp_header_t  	rtp_hdr;
	void*          	body;
}rtp_msg_t;



#ifdef __cplusplus
}
#endif

#endif


