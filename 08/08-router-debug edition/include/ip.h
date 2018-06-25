#ifndef __IP_H__
#define __IP_H__

#include <endian.h>

#include "base.h"
#include "types.h"
#include "checksum.h"
#include "ether.h"
#include "log.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
// #define IPPROTO_ICMP		1	// ICMP (Internet Control Message Protocol)
// #define IPPROTO_TCP		6	// TCP (Transport Control Protocol)
// #define IPPROTO_UDP		17	// UDP (User Datagram Protocol)
#define IPPROTO_OSPFv2		89 // Open Shortest Path First v2

// #include <netinet/ip.h>
#define IP_DF	0x4000		// Do not Fragment
struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    u8 tos;
    u16 tot_len;
    u16 id;
    u16 frag_off;
    u8 ttl;
    u8 protocol;
    u16 checksum;
    u32 saddr;
    u32 daddr;
};

#define IP_BASE_HDR_SIZE sizeof(struct iphdr)
#define IP_HDR_SIZE(hdr) (hdr->ihl * 4)
#define IP_DATA(hdr)	((char *)hdr + IP_HDR_SIZE(hdr))

#define IP_FMT	"%hhu.%hhu.%hhu.%hhu"
#define LE_IP_FMT_STR(ip) ((u8 *)&(ip))[3], \
						  ((u8 *)&(ip))[2], \
 						  ((u8 *)&(ip))[1], \
					      ((u8 *)&(ip))[0]

#define BE_IP_FMT_STR(ip) ((u8 *)&(ip))[0], \
						  ((u8 *)&(ip))[1], \
 						  ((u8 *)&(ip))[2], \
					      ((u8 *)&(ip))[3]

#define NET_IP_FMT_STR(ip)	BE_IP_FMT_STR(ip)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#	define HOST_IP_FMT_STR(ip)	LE_IP_FMT_STR(ip)
#elif __BYTE_ORDER == __BIG_ENDIAN
#	define HOST_IP_FMT_STR(ip)	BE_IP_FMT_STR(ip)
#endif

static inline u16 ip_checksum(struct iphdr *hdr)
{
	struct iphdr * ip = (struct iphdr *)malloc(IP_HDR_SIZE(hdr)+4);
	memcpy(ip, hdr, IP_HDR_SIZE(hdr));
	/*ip->tot_len = ntohs(ip->tot_len);
	ip->id = ntohs(ip->id);
	ip->saddr = ntohl(ip->saddr);
	ip->daddr = ntohl(ip->daddr);
	//ip->frag_off = ntohs(ip->frag_off);
	u16 * t = (u16 * )ip;
	for(int i = 0; i < hdr->ihl; i++)
		t[i] = ntohs(t[i]);*/
	u16 tmp = ip->checksum;
	ip->checksum = 0;
	u16 sum = checksum((u16 *)ip, ip->ihl * 4, 0);
	ip->checksum = tmp;
	//log(DEBUG,"ip packet header length %d",ip->ihl * 4);
	free(ip);

	return sum;
}

static inline struct iphdr *packet_to_ip_hdr(const char *packet)
{
	return (struct iphdr *)(packet + ETHER_HDR_SIZE);
}

void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto);
void handle_ip_packet(iface_info_t *iface, char *packet, int len);
void ip_send_packet(char *packet, int len);

#endif
