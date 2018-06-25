#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"


#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr * ip = packet_to_ip_hdr(in_pkt);
	char * packet_buf = (char * )malloc(ETHER_HDR_SIZE + ntohs(ip->tot_len) + 40);

	//copy eth and ip info
	memcpy(packet_buf, in_pkt, len);

	//initial ICMP header
	struct icmphdr * ich = (struct icmphdr *)(packet_buf + ETHER_HDR_SIZE + (ip->ihl * 4));
	ich->type = type;
	ich->code = code;

	//if not Ping packet
	if(type != ICMP_ECHOREPLY){
		memset((char *)ich + 4, 0, 4*sizeof(char));
	}

	//calculate checksum
	ich->checksum = icmp_checksum(ich, ntohs(ip->tot_len) - ip->ihl*4);

	//send
	ip_send_packet(packet_buf, len);
	
}
