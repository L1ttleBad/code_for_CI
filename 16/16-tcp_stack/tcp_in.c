#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <assert.h>
#include <stdlib.h>

// handling incoming packet for TCP_LISTEN state 	TODO
//
// 1. malloc a child tcp sock to serve this connection request; 
// 2. send TCP_SYN | TCP_ACK by child tcp sock;
// 3. hash the child tcp sock into established_table (because the 4-tuple 
//    is determined).
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	struct tcp_sock * child;
	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	u32 ip_tot_len = ntohs(ip->tot_len);
	u32 tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	//1
	child = alloc_tcp_sock();
	child->sk_sip = ntohl(ip->daddr);
	child->sk_sport = ntohs(tcp->dport);
	child->sk_dip = ntohl(ip->saddr);
	child->sk_dport = ntohs(tcp->sport);	
	child->snd_nxt = child->iss;
	child->parent = tsk;
	child->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
	//log(DEBUG,"listen get!!seq %d, rcv_nxt %d", ntohl(tcp->seq) ,child->rcv_nxt);
	child->snd_una = 0;	
	tcp_set_state(child, TCP_SYN_RECV);

	//2
	tcp_send_control_packet(child, TCP_SYN | TCP_ACK);

	//3
	tcp_hash(child);
	list_add_head(&child->list, &tsk->listen_queue);

	return;
	
}

// handling incoming packet for TCP_CLOSED state, by replying TCP_RST
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	tcp_send_reset(cb);
}

// handling incoming packet for TCP_SYN_SENT state TODO
//
// If everything goes well (the incoming packet is TCP_SYN|TCP_ACK), reply with 
// TCP_ACK, and enter TCP_ESTABLISHED state, notify tcp_sock_connect; otherwise, 
// reply with TCP_RST.
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	int ip_tot_len = ntohs(ip->tot_len);
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;
	
	if((TCP_SYN | TCP_ACK) != tcp->flags || ntohl(tcp->ack) != tsk->snd_nxt)
	{
		log(ERROR,"wrong syn reply!!ack %d, nxt %d", ntohl(tcp->ack) ,tsk->snd_nxt);
		tcp_send_reset(cb);
		return;
	}

	tsk->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
	tsk->snd_una = ntohl(tcp->ack) - 1;

	tcp_set_state(tsk, TCP_ESTABLISHED);

	tcp_send_control_packet(tsk, TCP_ACK);
	//tsk->snd_nxt++;

	wake_up(tsk->wait_connect);

	
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

// handling incoming ack packet for tcp sock in TCP_SYN_RECV state  TODO
//
// 1. remove itself from parent's listen queue;
// 2. add itself to parent's accept queue;
// 3. wake up parent (wait_accept) since there is established connection in the
//    queue.
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	struct iphdr * ip = packet_to_ip_hdr(packet);
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	int ip_tot_len = ntohs(ip->tot_len);
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	//remove it from listen queue
	if(!list_empty(&tsk->list))
		my_list_delete_entry(&tsk->list);

	tcp_sock_accept_enqueue(tsk);

	tsk->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
	tsk->snd_una = ntohl(tcp->ack) - 1;
	tcp_set_state(tsk, TCP_ESTABLISHED);

	wake_up(tsk->parent->wait_accept);
	return;	
		
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process an incoming packet as follows: TODO
// 	 1. if the state is TCP_CLOSED, hand the packet over to tcp_state_closed;
// 	 2. if the state is TCP_LISTEN, hand it over to tcp_state_listen;
// 	 3. if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent;
// 	 4. check whether the sequence number of the packet is valid, if not, drop
// 	    it;
// 	 5. if the TCP_RST bit of the packet is set, close this connection, and
// 	    release the resources of this tcp sock;
// 	 6. if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
// 	    as valid TCP_SYN has been processed in step 2 & 3;
// 	 7. check if the TCP_ACK bit is set, since every packet (except the first 
//      SYN) should set this bit;
//   8. process the ack of the packet: if it ACKs the outgoing SYN packet, 
//      establish the connection; (if it ACKs new data, update the window;)
//      if it ACKs the outgoing FIN packet, switch to correpsonding state;
//   9. (process the payload of the packet: call tcp_recv_data to receive data;)
//  10. if the TCP_FIN bit is set, update the TCP_STATE accordingly;
//  11. at last, do not forget to reply with TCP_ACK if the connection is alive.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	struct tcphdr * tcp = packet_to_tcp_hdr(packet);
	struct iphdr * ip = packet_to_ip_hdr(packet);
	int ip_tot_len = ntohs(ip->tot_len);
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	//5
	if(tcp->flags & TCP_RST)
	{
		
		if(!list_empty(&tsk->list))
				my_list_delete_entry(&tsk->list);
		
		
		tcp_unhash(tsk);
		
		tcp_bind_unhash(tsk);
		
		return;
	}

	tsk->snd_wnd = ntohs(tcp->rwnd);
		
	//1
	if(tsk->state == TCP_CLOSED)
	{
		tcp_state_closed(tsk, cb, packet);
		return;
	}

	//2
	if(tsk->state == TCP_LISTEN)
	{
		tcp_state_listen(tsk, cb, packet);
		return;
	}

	//3
	if(tsk->state == TCP_SYN_SENT)
	{
		tcp_state_syn_sent(tsk, cb, packet);
		return;
	}

	//4
	if((int32_t)(ntohl(tcp->seq) - tsk->rcv_nxt) < 0)
	{
		return;
	}

	//6
	if(tcp->flags & TCP_SYN)
	{
		tcp_send_reset(cb);

		//end 
		tcp_bind_unhash(tsk);
		
		tcp_unhash(tsk);
		
		if(!list_empty(&tsk->list))
			my_list_delete_entry(&tsk->list);

		free_tcp_sock(tsk);
		return;
	}

	//7
	if(!(tcp->flags & TCP_ACK))
		return;

	//8
	if((int32_t)(ntohl(tcp->ack) - tsk->snd_una) < 0)
		return;
	if(tsk->state == TCP_SYN_RECV)
	{
		tcp_set_state(tsk, TCP_ESTABLISHED);

		//remove it from listen queue
		if(!list_empty(&tsk->list))
			my_list_delete_entry(&tsk->list);

		tcp_sock_accept_enqueue(tsk);

		tsk->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
		tsk->snd_una = ntohl(tcp->ack) - 1;

		wake_up(tsk->parent->wait_accept);
		return;
	}
	if(tsk->state == TCP_FIN_WAIT_1)
	{
		tcp_set_state(tsk, TCP_FIN_WAIT_2);
		tsk->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
		tsk->snd_una = ntohl(tcp->ack) - 1;
		return;
	}
	if(tsk->state == TCP_LAST_ACK)
	{
		tcp_set_state(tsk, TCP_CLOSED);
		tsk->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
		tsk->snd_una = ntohl(tcp->ack) - 1;

		//end 
		tcp_bind_unhash(tsk);
		
		tcp_unhash(tsk);
		
		if(!list_empty(&tsk->list))
			my_list_delete_entry(&tsk->list);

		free_tcp_sock(tsk);
		return;
	}

	//9
	if(tcp_data_len > 0)
	{
		write_ring_buffer(tsk->rcv_buf, ((char *) tcp) + TCP_HDR_SIZE(tcp), tcp_data_len);
		log(DEBUG,"buf writen len %d", tcp_data_len);
		tsk->rcv_wnd -= tcp_data_len;
	}
	//tsk->snd_wnd = ntohs(tcp->rwnd);

	//10
	if(tcp->flags & TCP_FIN)
	{
		if(tsk->state == TCP_ESTABLISHED)
		{
			tsk->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
			tsk->snd_una = ntohl(tcp->ack) - 1;

			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
			tcp_set_state(tsk, TCP_LAST_ACK);
			return;
		}
		
		if(tsk->state == TCP_FIN_WAIT_2)
		{
			tsk->rcv_nxt = ntohl(tcp->seq) + ((TCP_SYN | TCP_FIN) & (tcp->flags) ? 1 : tcp_data_len) ;
			tsk->snd_una = ntohl(tcp->ack) - 1;

			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_TIME_WAIT);
			 tcp_set_timewait_timer(tsk);
			return;
		}	

		assert(0);

	}

	//11 for normal data
	tsk->rcv_nxt = ntohl(tcp->seq) + (tcp_data_len ? tcp_data_len : (TCP_SYN | TCP_FIN) & (tcp->flags)) ;
	tsk->snd_una = ntohl(tcp->ack) - 1;
	
	if(tcp_data_len > 0)
		tcp_send_control_packet(tsk, TCP_ACK);
	return;

	
}
