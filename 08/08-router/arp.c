#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include "ip.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	char * buf = (char * ) malloc(64);
	memset(buf, 1, ETH_ALEN);
	memcpy(buf + ETH_ALEN, iface->mac, ETH_ALEN);
	struct ether_header * eh =  (struct ether_header * ) buf;
	eh->ether_type = htons(0x0806);
	struct ether_arp * arp = (struct ether_arp * )(buf + ETHER_HDR_SIZE);
	arp->arp_hrd = htons(0x0001);
	arp->arp_pro = htons(0x0800);
	arp->arp_hln = 6;
	arp->arp_pln = 4;
	arp->arp_op = htons(0x0001);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	arp->arp_tpa = htonl(dst_ip);
	memset(arp->arp_tha, 0, ETH_ALEN);

	//send request
	iface_send_packet(iface, buf, 42);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	char * buf = (char * ) malloc(64);

	//set ETH
	memcpy(buf, &req_hdr->arp_tha, ETH_ALEN);
	memcpy(buf + ETH_ALEN, &iface->mac, ETH_ALEN);
	struct ether_header * eh =  (struct ether_header * ) buf;
	eh->ether_type = htons(0x0806);
	memcpy(buf + ETHER_HDR_SIZE, req_hdr, sizeof(struct ether_arp));

	//send packet
	iface_send_packet(iface, buf, 42);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	log(DEBUG, "arp packet recived");
	struct ether_arp * arp = (struct ether_arp * )(packet + ETHER_HDR_SIZE);

	//if it is request
	if(arp->arp_op == htons(0x0001) && arp->arp_tpa == htonl(iface->ip)){
		log(DEBUG, "it is echo to %x", iface->ip);
		struct ether_arp buf;
		memcpy(&buf, arp, 6);
		buf.arp_op = htons(0x0002);
		memcpy(buf.arp_sha, iface->mac, ETH_ALEN);
		buf.arp_spa = htonl(iface->ip);
		memcpy(buf.arp_tha, arp->arp_sha, 10);
		arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
		arp_send_reply(iface, &buf);
		
	}
	else{
		arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
	}
	
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);	
	log(DEBUG,"finded: %d ,the correspongding mac is %d %d %d %d %d %d", found, dst_mac[0] , dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
	if (found) {
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		arpcache_append_packet(iface, dst_ip, packet, len);
	}

}
