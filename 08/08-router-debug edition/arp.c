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
	//log(DEBUG,"sending arp requset ,hrd %x, pro %x, hln %x, pln %x, op%x, spa %x, tpa %x", 
	//	arp->arp_hrd,arp->arp_pro,arp->arp_hln,arp->arp_pln,arp->arp_op,arp->arp_spa,arp->arp_tpa);

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
	//struct ether_arp * r =  (struct ether_arp * ) (buf + ETHER_HDR_SIZE) ;
	//log(DEBUG,"sending packet , dmac: %x, smac: %x, ptype: %x, hrd %x, pro %x, hln %x, pln %x, op%x, spa %x, tpa %x", eh->ether_dhost, eh->ether_shost, eh->ether_type,
	//	r->arp_hrd,r->arp_pro,r->arp_hln,r->arp_pln,r->arp_op,r->arp_spa,r->arp_tpa);

	//send packet
	iface_send_packet(iface, buf, 42);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	log(DEBUG, "arp packet recived");
	struct ether_arp * arp = (struct ether_arp * )(packet + ETHER_HDR_SIZE);
	//u32 sender = ntohl(arp->arp_spa);


	//if it is request
	if(arp->arp_op == htons(0x0001) && arp->arp_tpa == htonl(iface->ip)){
		log(DEBUG, "it is echo to %x", iface->ip);
		struct ether_arp buf;
		memcpy(&buf, arp, 6);
		buf.arp_op = htons(0x0002);
		memcpy(buf.arp_sha, iface->mac, ETH_ALEN);
		buf.arp_spa = htonl(iface->ip);
		memcpy(buf.arp_tha, arp->arp_sha, 10);
		//log(DEBUG,"offset of sha is %x, %x", &arp->arp_sha , arp);
		//log(DEBUG,"sending packet ,hrd %x, pro %x, hln %x, pln %x, op%x, spa %x, tpa %x", 
		//buf.arp_hrd,buf.arp_pro,buf.arp_hln,buf.arp_pln,buf.arp_op,buf.arp_tpa,buf.arp_tpa);
		arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
		arp_send_reply(iface, &buf);
		
	}
	else{
		log(DEBUG, "it is reply from %x, op is %d, arp->tpa is %x, iface->ip is %x", ntohl(arp->arp_spa), ntohs(arp->arp_op),ntohl(arp->arp_tpa),iface->ip);
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
	//log(DEBUG,"start look up mac for ip %x", dst_ip);
	int found = arpcache_lookup(dst_ip, dst_mac);	
	log(DEBUG,"finded: %d ,the correspongding mac is %d %d %d %d %d %d", found, dst_mac[0] , dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
	if (found) {
		//log(DEBUG, "iface send packet , iface ip : "IP_FMT" ", HOST_IP_FMT_STR(iface->ip));
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		//memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}

}
