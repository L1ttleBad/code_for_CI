/* server application */
 
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
 
int main(int argc, const char *argv[])
{
    uint32_t sock,sock2;
    struct sockaddr_in wo1,wo2;
	char path[] = "war_and_peace.txt";
	char conf[] = "workers.conf";
	char ip1_buf[50];
	char ip2_buf[50];
	uint32_t counter[26];
	uint32_t counter_buf[26];
	uint32_t i;
     
    // create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket");
    }

	sock2 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock2 == -1) {
        printf("Could not create socket");
    }		
    printf("Socket created\n");	
	
	
	// read workers' ip
	FILE *confp = fopen(conf, "r");
	fscanf(confp,"%s\n%s", ip1_buf, ip2_buf);
	fclose(confp);
	printf("ip %s , %s \n", ip1_buf, ip2_buf);

	
	// read file and decide the work assignment
	FILE *fp = fopen(path, "r");
	fseek(fp,0,SEEK_END);
	uint32_t total_len = ftell(fp);
	printf("total_len : %d\n", total_len);
	    
	fclose(fp);
	
	uint32_t half_len = htonl(total_len/2);
	total_len = htonl(total_len);
	uint32_t trash = htonl(0);
	
	uint32_t len_message = sizeof(path) + 8;
	len_message = htonl(len_message);	

	
	// start to connect
    wo1.sin_addr.s_addr = inet_addr(ip1_buf);
    wo1.sin_family = AF_INET;
    wo1.sin_port = htons( 12345 );


    // connect to remote worker1
    if (connect(sock, (struct sockaddr *)&wo1, sizeof(wo1)) < 0) {
        perror("connect failed. Error");
        return 1;
    }
	
	wo2.sin_addr.s_addr = inet_addr(ip2_buf);
    wo2.sin_family = AF_INET;
    wo2.sin_port = htons( 12345 );
 
    // connect to remote worker2
    if (connect(sock2, (struct sockaddr *)&wo2, sizeof(wo2)) < 0) {
        perror("connect failed. Error");
        return 1;
    }
     
    printf("Connected\n");
	
	// assign counting work
    send(sock, &len_message, 4, 0);
	send(sock, path, sizeof(path), 0);
	send(sock, &trash, 4, 0);
	send(sock, &half_len, 4, 0);
	
	send(sock2, &len_message, 4, 0);
	send(sock2, path, sizeof(path), 0);
	send(sock2, &half_len, 4, 0);
	send(sock2, &total_len, 4, 0);	
	
	
	// receive counting result	
	recv(sock, counter_buf, 104, 0);
	for(i = 0; i < 26; i++)
		counter[i] = 0;	
	for(i = 0; i < 26; i++)
		counter[i] += ntohl(counter_buf[i]);
	printf("worker1 finished !!!\n");

	close(sock);
	
	recv(sock2, counter_buf, 104, 0);
	for(i = 0; i < 26; i++)
		counter[i] += ntohl(counter_buf[i]);
	printf("worker2 finished !!!\n");	
	
	close(sock2);
     
    
	// print counting result
	for(i = 0; i < 26; i++)
		printf("%c , %d \n", i + 'a', counter[i]);


    return 0;
}
