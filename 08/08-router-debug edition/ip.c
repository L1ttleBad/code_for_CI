#include "ip.h"
#include "icmp.h"
#include "packet.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "log.h"

#include <stdlib.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(len);
	ip->id = rand();
	ip->frag_off = htons(IP_DF);
	ip->ttl = DEFAULT_TTL;
	ip->protocol = proto;
	ip->saddr = htonl(saddr);
	ip->daddr = htonl(daddr);
	ip->checksum = ip_checksum(ip);
}

// lookup in the routing table, to find the entry with the same and longest prefix.
// the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst)
{
	rt_entry_t * entry = NULL;
	rt_entry_t * match_entry = NULL;
	u32 net;
	u32 mask = 0;

	//travel through each entry finding the longest perfix match
	list_for_each_entry(entry, &rtable, list)
	{
		net = entry->dest & entry->mask;

		//if not match
		if((dst & entry->mask) != net){
			continue;
		}

		//if not longest
		if(entry->mask <= mask){
			continue;
		}

		mask = entry->mask;
		match_entry = entry;
	}
	return match_entry;
}

// forward the IP packet from the interface specified by longest_prefix_match, 
// when forwarding the packet, you should check the TTL, update the checksum,
// determine the next hop to forward the packet, then send the packet by 
// iface_send_packet_by_arp
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr * ip = packet_to_ip_hdr(packet);
	//log(DEBUG,"old check sum %x", ntohs(ip->checksum));
	ip->checksum = ip_checksum(ip);
	//log(DEBUG,"new check sum %x", ntohs(ip->checksum));
	ip_send_packet(packet, len);
}

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr * ip = packet_to_ip_hdr(packet);
	log(DEBUG, "handling ip packet, dad ip "IP_FMT", sad "IP_FMT, NET_IP_FMT_STR(ip->daddr),NET_IP_FMT_STR(ip->saddr));

	//log(DEBUG,"ICMP message type %d, code %d \n ", ich->type, ich->code);
	//uint8_t * trash = (uint8_t * ) packet;
	//for(int j = 0; j < 98 ; j++)
		//log(DEBUG,"ICMP message %d %x ", j, trash[j]);
	u32 dst = ntohl(ip->daddr);
	rt_entry_t *entry = longest_prefix_match(dst);
		if (!entry) {
			log(ERROR, "Could not find forwarding rule for IP (dst:"IP_FMT") packet.", 
				HOST_IP_FMT_STR(dst));
						
			//make up IP Header info of ICMP packet
			char * packet_buf = (char * )malloc(ETHER_HDR_SIZE + ntohs(ip->tot_len) + 40);
			memset(packet_buf, 0, ETHER_HDR_SIZE*sizeof(char));
			memcpy(packet_buf + ETHER_HDR_SIZE*sizeof(char), packet + ETHER_HDR_SIZE, ntohs(ip->tot_len));
			memcpy(packet_buf + ETHER_HDR_SIZE*sizeof(char) + ip->ihl*4 + 8, packet + ETHER_HDR_SIZE, ip->ihl*4 + 8);
			ip = packet_to_ip_hdr(packet_buf);
			u32 tmp = ip->daddr;
			ip->ttl = DEFAULT_TTL;
			ip->daddr = ip->saddr;
			//ip->saddr = htonl(req->iface->ip);
			ip->saddr = tmp;
			ip->tot_len = htons(ip->ihl*4 + 8 + ip->ihl*4 + 8);
			ip->checksum = ip_checksum(ip);
			icmp_send_packet(packet_buf, ETHER_HDR_SIZE + ntohs(ip->tot_len), 0x03, 0x02);
			return ;
		}
	log(ERROR, "the tll is %d", 
				ip->ttl);
	//if out of ttl
	if(--ip->ttl <= 0){
	
		/*rt_entry_t *entry = longest_prefix_match(dst);
		if (!entry) {
			log(ERROR, "Could not find forwarding rule for IP (dst:"IP_FMT") packet.", 
				HOST_IP_FMT_STR(dst));
			//free(packet);
			return ;
		}

		u32 next_hop = entry->gw;
		if (!next_hop)
			next_hop = dst;*/
						
		//make up IP Header info of ICMP packet
		char * packet_buf = (char * )malloc(ETHER_HDR_SIZE + ntohs(ip->tot_len) + 40);
		memset(packet_buf, 0, ETHER_HDR_SIZE*sizeof(char));
		memcpy(packet_buf + ETHER_HDR_SIZE*sizeof(char), packet + ETHER_HDR_SIZE, ntohs(ip->tot_len));
		memcpy(packet_buf + ETHER_HDR_SIZE*sizeof(char) + ip->ihl*4 + 8, packet + ETHER_HDR_SIZE, ip->ihl*4 + 8);
		ip = packet_to_ip_hdr(packet_buf);
		ip->daddr = ip->saddr;
		//ip->saddr = htonl(req->iface->ip);
		ip->saddr = iface->ip;
		ip->protocol = 1;
		ip->tot_len = htons(ip->ihl*4 + 8 + ip->ihl*4 + 8);
		ip->checksum = ip_checksum(ip);
		
		//send
		icmp_send_packet(packet_buf, ntohs(ip->tot_len) + ETHER_HDR_SIZE, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		return ;
	}

	//if it is ICMP packet
	if(ntohl(ip->daddr) == iface->ip){
		struct icmphdr * ich = (struct icmphdr *)(ip + 1);
		//log(DEBUG,"ICMP message &ip %x, ip ihl * 4 %d, &ich %x  ", ip, ip->ihl * 4, ich);
		
		u8 type = ich->type;
		if(type == 0){
			log(DEBUG,"ICMP received, type : 0, echo reply received \n ");
		}
		else if(type == 3){
			if(ich->code == 0){
				log(DEBUG,"ICMP received, type : 3, NET Unreachable \n ");
			}
			else{
				log(DEBUG,"ICMP received, type : 3, HOST Unreachable \n ");
			}
		}
		else if(type == 11){
			log(DEBUG,"ICMP received, type : 11,Time Exceeded  \n ");
		}
		else if(type == 8){
			log(DEBUG,"ICMP received, type : 8, echo received  \n ");
			u32 dst = ntohl(ip->saddr);
			/*rt_entry_t *entry = longest_prefix_match(dst);
			if (!entry) {
				log(ERROR, "Could not find forwarding rule for IP (dst:"IP_FMT") packet.", 
					HOST_IP_FMT_STR(dst));
				//free(packet);
				return ;
			}

			u32 next_hop = entry->gw;
			if (!next_hop)
				next_hop = dst;*/
			ip->saddr = htonl(iface->ip);
			ip->daddr = htonl(dst);
			
			//make up IP Header info of ICMP packet
			ip->checksum = ip_checksum(ip);
			char * packet_buf = (char * )malloc(ETHER_HDR_SIZE + ntohs(ip->tot_len) + 16);
			memset(packet_buf, 0, ETHER_HDR_SIZE*sizeof(char));
			memcpy(packet_buf + ETHER_HDR_SIZE*sizeof(char), packet + ETHER_HDR_SIZE, ntohs(ip->tot_len));
			
			//send
			icmp_send_packet(packet_buf, htons(ip->tot_len) + ETHER_HDR_SIZE, ICMP_ECHOREPLY, ICMP_ECHOREPLY);
			return ;
		}

	}
	//if not, forwarding the packet
	else{
		ip_forward_packet(ip->daddr, packet, len);
	}
	
}

// send IP packet
//
// Different from ip_forward_packet, ip_send_packet sends packet generated by
// router itself. This function is used to send ICMP packets.
void ip_send_packet(char *packet, int len)
{
	//print_rtable();

	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 dst = ntohl(ip->daddr);
	log(DEBUG, "sending IP (dst:"IP_FMT") packet.", 
				HOST_IP_FMT_STR(dst));
	rt_entry_t *entry = longest_prefix_match(dst);
	if (!entry) {
		log(ERROR, "Could not find forwarding rule for IP (dst:"IP_FMT") packet.", 
				HOST_IP_FMT_STR(dst));
		
		free(packet);
		return ;
	}

	u32 next_hop = entry->gw;
	if (!next_hop)
		next_hop = dst;

	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = ntohs(ETH_P_IP);
	memcpy(eh->ether_shost, entry->iface->mac, ETH_ALEN);

	//log(DEBUG,"start arp sending");
	iface_send_packet_by_arp(entry->iface, next_hop, packet, len);

}
