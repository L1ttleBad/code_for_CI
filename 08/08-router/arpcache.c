#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"
#include "log.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the hash table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{

	pthread_mutex_lock(&arpcache.lock);


	if(arpcache.entries[ip4%32].ip4 == ip4){
		for(int i = 0; i < ETH_ALEN; i++){
			mac[i] = arpcache.entries[ip4%32].mac[i];
		}
		pthread_mutex_unlock(&arpcache.lock);
		return 1;
	}

	pthread_mutex_unlock(&arpcache.lock);

		
	return 0;
}

// append the packet to arpcache
//
// Lookup in the hash table which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	pthread_mutex_lock(&arpcache.lock);

	//if corresponding arpcache entry exists, find req
	struct arp_req * req = (struct arp_req *)(&arpcache.req_list);	
	struct arp_req * r;
	int matched = 0;
	list_for_each_entry(r, &arpcache.req_list, list){
		if(r->ip4 == ip4){
			if(r->iface == iface){
				matched = 1;
				break;
			}
		}
	}
	req = r;

	if(matched == 0){
	//if not, add new req
		struct arp_req * new_req = (struct arp_req *)malloc(sizeof(struct arp_req));
		new_req->iface = iface;
		new_req->ip4 = ip4;
		new_req->sent = time(NULL);
		new_req->retries = 0;
		new_req->cached_packets.prev = &new_req->cached_packets;
		new_req->cached_packets.next = &new_req->cached_packets;
		list_add_tail( (struct list_head *)new_req, (struct list_head *)req);
		req = new_req;
	}

	//store packet to req list
	struct cached_pkt * pkt = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
	pkt->packet = (char *)malloc(len);
	memcpy(pkt->packet, packet, len);
	pkt->len = len;
	list_add_tail( (struct list_head *)pkt, (struct list_head *)&req->cached_packets);

	//send arp request
	req->retries += 1;
	arp_send_request(iface, ip4);

	pthread_mutex_unlock(&arpcache.lock);

		
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);

	arpcache.entries[ip4%32].ip4 = ip4;
	for(int i = 0; i < ETH_ALEN; i++){
		arpcache.entries[ip4%32].mac[i] = mac[i];
	}
	arpcache.entries[ip4%32].added = time(NULL);
	arpcache.entries[ip4%32].valid = 1;

	struct arp_req * req;
	struct cached_pkt * pkt;
	struct arp_req * l;
	list_for_each_entry_safe(req, l, &arpcache.req_list, list){
		if(req->ip4 == ip4){
			list_for_each_entry(pkt, (struct list_head *)&req->cached_packets, list){
				pthread_mutex_unlock(&arpcache.lock);
				iface_send_packet_by_arp(req->iface, ip4, pkt->packet, pkt->len);
				pthread_mutex_lock(&arpcache.lock);
			}
			delete_list(&req->cached_packets, struct cached_pkt, list);
			list_delete_entry((struct list_head *)req);
			free(req);
		}
	}
	
	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	u32 tmp;
	while (1) {
		sleep(1);
		pthread_mutex_lock(&arpcache.lock);
		for(int i = 0; i < 32; i++){
			if((time(NULL) - arpcache.entries[i].added) > 15 && arpcache.entries[i].valid){
				 arpcache.entries[i].valid = 0;
			}
		}

		struct arp_req * req;
		struct cached_pkt * pkt;
		struct arp_req * l;
		list_for_each_entry_safe(req, l, &arpcache.req_list, list){
			if(time(NULL) - req->sent > 1){
				if(req->retries < 5){				
					//send arp request
					arp_send_request(req->iface, req->ip4);
				}
				else{
					list_for_each_entry(pkt, (struct list_head *)&req->cached_packets, list){
						pthread_mutex_unlock(&arpcache.lock);
						struct iphdr * ip = packet_to_ip_hdr(pkt->packet);
						
						//make up IP Header info of ICMP packet
						char * packet_buf = (char * )malloc(ETHER_HDR_SIZE + ntohs(ip->tot_len) + 40);
						memset(packet_buf, 0, ETHER_HDR_SIZE*sizeof(char));
						memcpy(packet_buf + ETHER_HDR_SIZE*sizeof(char), pkt->packet + ETHER_HDR_SIZE, ntohs(ip->tot_len));
						memcpy(packet_buf + ETHER_HDR_SIZE*sizeof(char) + ip->ihl*4 + 8, pkt->packet + ETHER_HDR_SIZE, ip->ihl*4 + 8);
						ip = packet_to_ip_hdr(packet_buf);
						tmp = ip->daddr;
						ip->ttl = DEFAULT_TTL;
						ip->daddr = ip->saddr;
						ip->saddr = tmp;
						ip->tot_len = htons(ip->ihl*4 + 8 + ip->ihl*4 + 8);
						ip->checksum = ip_checksum(ip);
						icmp_send_packet(packet_buf, ETHER_HDR_SIZE + ntohs(ip->tot_len), 0x03, 0x01);
						pthread_mutex_lock(&arpcache.lock);
					}	
					delete_list(&req->cached_packets, struct cached_pkt, list);
					list_delete_entry((struct list_head *)req);
					free(req);
				}
			}
		}

		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
