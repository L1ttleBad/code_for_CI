/* client application */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// finish counting work for corresponding input counter buf, file path, counting range
void count( uint32_t * counter, char * path, uint32_t start, uint32_t end)
{
	char buffer;
	FILE *fp = fopen(path, "r");
	fseek(fp, start, SEEK_SET);
	end -= start;
	while(end--)
	{
		fread(&buffer, 1, 1, fp);
		if( buffer >= 'a' && buffer <= 'z')         // count lower case letters
			counter[(buffer-'a')%26]++;
		else if( buffer >= 'A' && buffer <= 'Z')    // count upper case letters
			counter[(buffer-'A')%26]++;
	}
	fclose(fp);
}
 
int main(int argc, char *argv[])
{
    uint32_t s,host;
    struct sockaddr_in server,client;
    char server_send[2000];
	uint32_t len_message, start, end;
	uint32_t counter[26];
	uint32_t i;
	
	
    // create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket");
		return -1;
    }
    printf("Socket created\n");
     
	 
    // prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(12345);
     
	 
    // bind
    if (bind(s,(struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind failed. Error");
        return -1;
    }
    printf("bind done");
     
	 
    // listen
    listen(s, 3);
     
	 
    // accept and incoming connection
    printf("Waiting for incoming connections...\n");
     
	 
    // accept connection from an incoming client
    uint32_t c = sizeof(struct sockaddr_in);
    if ((host = accept(s, (struct sockaddr *)&client, (socklen_t *)&c)) < 0) {
        perror("accept failed");
        return 1;
    }
    printf("Connection accepted\n"); 

     
    // keep communicating with server
    while(1) {

         
        // receive message lenth from server
        if (recv(host, &len_message, 4, 0) <= 0) {
            printf("recv failed");
            break;
        }
		len_message = ntohl( len_message );
		printf("len_message: %d\n", len_message);
		
		
		// receive file path
		if (recv(host, server_send, len_message-8, 0) < 0) {
            printf("recv failed");
            break;
        }
		printf("path : %s\n",server_send);
		
		
		// receive start and end point 
		if (recv(host, &start, 4, 0) < 0) {
            printf("recv failed");
            break;
        }
		if (recv(host, &end, 4, 0) < 0) {
            printf("recv failed");
            break;
        }
		start = ntohl( start );
		end = ntohl( end );
		printf(" start : %d  end : %d \n", start, end);
		
		
		// initialize counter
		for( i = 0; i < 26; i++)
			counter[i] = 0;
		
		
		// start counting work
		count(counter, server_send, start, end);
		
		for( i = 0; i < 26; i++)
			counter[i] = htonl(counter[i]);
		
        // send counting result
        if (send(host, counter, 104, 0) < 0) {
            printf("Send failed");
            return 1;
        }
         		
        printf("counting message sended!!!!\n ");

    }
     
    close(host);
    return 0;
}
