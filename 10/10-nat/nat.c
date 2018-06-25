#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;
static uint16_t assigned_port;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	//log(DEBUG, "deciding dir");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	//struct tcphdr * tcp = packet_to_tcp_hdr(packet);

	//if it's out packet
	if(longest_prefix_match(ntohl(ip->saddr))->iface->index == nat.internal_iface->index \
		&& longest_prefix_match(ntohl(ip->daddr))->iface->index == nat.external_iface->index){
		return DIR_OUT;
	}

	//if it's in packet
	if(longest_prefix_match(ntohl(ip->saddr))->iface->index == nat.external_iface->index \
		&& ntohl(ip->daddr) == nat.external_iface->ip){
		return DIR_IN;
	}	
	
	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	//log(DEBUG, "doing translation");

	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	pthread_mutex_lock(&nat.lock);
	
	if(dir == DIR_OUT){
		//if map not exist
		if(!nat.nat_mapping_list[(ntohl(ip->daddr) + ntohs(tcp->dport)) % 256  ] || ((struct nat_mapping *)nat.nat_mapping_list[(ntohl(ip->daddr) + ntohs(tcp->dport)) % 256  ])->internal_ip != ntohl(ip->saddr)){
			struct nat_mapping * nm = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
			nat.nat_mapping_list[(ntohl(ip->daddr) + ntohs(tcp->dport)) % 256  ] = (struct list_head *) nm;

			nm->internal_ip = ntohl(ip->saddr);
			nm->internal_port = ntohs(tcp->sport);
			nm->external_ip = nat.external_iface->ip;

			//assign port
			do{
				nm->external_port = ++assigned_port;
				log(DEBUG, "current assigned_port %d state: %d ",assigned_port,nat.assigned_ports[assigned_port]);
			}while(nat.assigned_ports[assigned_port] == 1);
			nat.assigned_ports[assigned_port] = 1;
	
			nm->update_time = time(NULL);
			nm->conn.internal_ack = 0;
			nm->conn.internal_fin = 0;
			nm->conn.internal_seq_end = 0;
			nm->conn.external_ack = 0;
			nm->conn.external_fin = 0;
			nm->conn.external_seq_end = 0;
		}

		struct nat_mapping * nm = (struct nat_mapping *)nat.nat_mapping_list[(ntohl(ip->daddr) + ntohs(tcp->dport)) % 256  ];

		//update ip&tcp head
		ip->saddr = htonl(nm->external_ip);
		tcp->sport = htons(nm->external_port);
		ip->checksum = ip_checksum(ip);
		tcp->checksum = tcp_checksum(ip, tcp);
			
		
		if(tcp->flags & TCP_RST){
			nat.assigned_ports[nm->external_port] = 0;
			free(nm);
			ip_send_packet(packet, len);
			return;
		}
		
		if(tcp->flags & TCP_ACK){
			nm->conn.internal_ack = ntohl(tcp->ack);
		}
		
		if(tcp->flags & TCP_FIN){
			nm->conn.internal_fin = 1;
		}
		
		nm->update_time = time(NULL);
		nm->conn.internal_seq_end = ntohl(tcp->seq);
	}

	if(dir == DIR_IN){
		//if map not exist
		if(!nat.nat_mapping_list[(ntohl(ip->saddr) + ntohs(tcp->sport)) % 256  ] || ((struct nat_mapping *)nat.nat_mapping_list[(ntohl(ip->saddr) + ntohs(tcp->sport)) % 256  ])->external_port != ntohs(tcp->dport)){
			icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
			return;
		}

		struct nat_mapping * nm = (struct nat_mapping *)nat.nat_mapping_list[(ntohl(ip->saddr) + ntohs(tcp->sport)) % 256  ];

		//update ip&tcp head
		ip->daddr = htonl(nm->internal_ip);
		tcp->dport = htons(nm->internal_port);
		ip->checksum = ip_checksum(ip);
		tcp->checksum = tcp_checksum(ip, tcp);
			
		
		if(tcp->flags & TCP_RST){
			nat.assigned_ports[nm->external_port] = 0;
			free(nm);
			ip_send_packet(packet, len);
			return;
		}
		
		if(tcp->flags & TCP_ACK){
			nm->conn.external_ack = ntohl(tcp->ack);
		}
		
		if(tcp->flags & TCP_FIN){
			nm->conn.external_fin = 1;
		}

		nm->update_time = time(NULL);
		nm->conn.external_seq_end = ntohl(tcp->seq);
	}

	ip_send_packet(packet, len);
	pthread_mutex_unlock(&nat.lock);
			
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	uint16_t i;
	while (1) {
		pthread_mutex_lock(&nat.lock);
		for(i = 0; i < 256; i++){
			//if nat map exist
			if(nat.nat_mapping_list[i]){	
				//if nat map out of time
				if(time(NULL) - ((struct nat_mapping *)nat.nat_mapping_list[i])->update_time > 60){
					nat.assigned_ports[ ((struct nat_mapping *)nat.nat_mapping_list[i])->external_port] = 0;
					free((struct nat_mapping *)nat.nat_mapping_list[i]);
					nat.nat_mapping_list[i] = NULL;
				}
				//if nat tcp fin
				else if(((struct nat_mapping *)nat.nat_mapping_list[i])->conn.internal_fin && ((struct nat_mapping *)nat.nat_mapping_list[i])->conn.external_fin ){
					nat.assigned_ports[ ((struct nat_mapping *)nat.nat_mapping_list[i])->external_port] = 0;
					free((struct nat_mapping *)nat.nat_mapping_list[i]);
					nat.nat_mapping_list[i] = NULL;
				}
			}
		}
		pthread_mutex_unlock(&nat.lock);
		sleep(1);
	}

	return NULL;
}

// initialize nat table
void nat_table_init()
{
	memset(&nat, 0, sizeof(nat));
	assigned_port = 0;

	//for (int i = 0; i < HASH_8BITS; i++)
	//	init_list_head(&nat.nat_mapping_list[i]);

	nat.internal_iface = if_name_to_iface("n1-eth0");
	nat.external_iface = if_name_to_iface("n1-eth1");
	if (!nat.internal_iface || !nat.external_iface) {
		log(ERROR, "Could not find the desired interfaces for nat.");
		exit(1);
	}

	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

// destroy nat table
void nat_table_destroy()
{
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		//struct list_head *head = &nat.nat_mapping_list[i];
		//struct nat_mapping *mapping_entry, *q;
		nat.nat_mapping_list[i] =NULL;
		//list_for_each_entry_safe(mapping_entry, q, head, list) {
		//	list_delete_entry(&mapping_entry->list);
		//	free(mapping_entry);
		//}
	}

	pthread_kill(nat.thread, SIGTERM);

	pthread_mutex_unlock(&nat.lock);
}
