#include "mac.h"
#include "headers.h"
#include "log.h"

mac_port_map_t mac_port_map;

void init_mac_hash_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	pthread_mutexattr_init(&mac_port_map.attr);
	pthread_mutexattr_settype(&mac_port_map.attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mac_port_map.lock, &mac_port_map.attr);

	pthread_create(&mac_port_map.tid, NULL, sweeping_mac_port_thread, NULL);
}

void destory_mac_hash_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *tmp, *entry;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if (!entry) 
			continue;

		tmp = entry->next;
		while (tmp) {
			entry->next = tmp->next;
			free(tmp);
			tmp = entry->next;
		}
		free(entry);
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

//search for corresponding iface. if not exist, return NULL
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&mac_port_map.lock);
	iface_info_t * iface = NULL;
	
	//if corresponding iface exist
	if(mac_port_map.hash_table[mac[0]])
	{
		for(i = 0; i < ETH_ALEN; i++ )
			if(mac_port_map.hash_table[mac[0]]->mac[i] != mac[i])
				return NULL;
		iface = mac_port_map.hash_table[mac[0]]->iface;
		mac_port_map.hash_table[mac[0]]->visited = time(NULL);
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return iface;
}

//insert new transform table entry
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	static int i;
	
	//malloc new entry
	mac_port_entry_t * entry = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t));
	pthread_mutex_lock(&mac_port_map.lock);
	
	//free existed entry
	if(mac_port_map.hash_table[mac[0]])
		free(mac_port_map.hash_table[mac[0]]);
	
	//assign hast_table entry and its predecessor
	mac_port_map.hash_table[mac[0]] = entry;
	if(mac_port_map.hash_table[(i-1)%HASH_8BITS])
		mac_port_map.hash_table[(i-1)%HASH_8BITS]->next = entry;
	
	//assign entry details
	for(i = 0; i < ETH_ALEN; i++ )
		mac_port_map.hash_table[mac[0]]->mac[i] = mac[i];
	mac_port_map.hash_table[mac[0]]->iface = (iface_info_t *)malloc(sizeof(iface_info_t));
	memcpy(mac_port_map.hash_table[mac[0]]->iface, iface, sizeof(iface_info_t));
	mac_port_map.hash_table[mac[0]]->next = mac_port_map.hash_table[(mac[0] + 1) % HASH_8BITS];
	mac_port_map.hash_table[mac[0]]->visited = time(NULL);
	pthread_mutex_unlock(&mac_port_map.lock);

}

void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		while (entry) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));

			entry = entry->next;
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

//remove aged entry 
int sweep_aged_mac_port_entry()
{
	static int i;
	time_t now = time(NULL);
	pthread_mutex_lock(&mac_port_map.lock);
	
	//traversal the table
	for(i = 0; i < HASH_8BITS; i++ )
	{
		
		//if not exist
		if(!mac_port_map.hash_table[i])
			continue;
		
		//if aged
		if((now - mac_port_map.hash_table[i]->visited) > 30)
		{
			free(mac_port_map.hash_table[i]);
			mac_port_map.hash_table[i] = NULL;
			if(mac_port_map.hash_table[(i-1)%HASH_8BITS])
				mac_port_map.hash_table[(i-1)%HASH_8BITS]->next = NULL;
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return 0;
}

void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.\n", n);
	}

	return NULL;
}
