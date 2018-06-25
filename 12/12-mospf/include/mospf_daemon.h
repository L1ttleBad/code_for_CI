#ifndef __MOSPF_DAEMON_H__
#define __MOSPF_DAEMON_H__

#include "base.h"
#include "types.h"
#include "list.h"
#define MAX_DIST 65536
#define BAD_GW 0xffffffff

void mospf_init();
void mospf_run();
void handle_mospf_packet(iface_info_t *iface, char *packet, int len);
void generate_rt();

struct dist_entry{
	u32 rid;
	u32 dist;
	int visited;
	u32 gw;
};


#endif
