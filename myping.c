/*****************************************************************************/
/*** myping.c                                                              ***/
/***                                                                       ***/
/*** Use the ICMP protocol to request "echo" from destination.             ***/
/*** Compile as: make run                                                  ***/
/*** Run as: sudo ./myping                                                 ***/
/*****************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

// Define the Packet Constants
// ping packet size
#define PING_PKT_S 64
// Automatic port number
#define PORT_NO 0

// Automatic port number
#define PING_SLEEP_RATE 1000000

// Gives the timeout delay for receiving packets
// in seconds
#define RECV_TIMEOUT 1

// Define the Ping Loop
int pingloop=1;


// ping packet structure
struct ping_pkt{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len){
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF); // add hi 16 to low 16
    sum += (sum >> 16); // add carry
    result = ~sum; // truncate to 16 bits
    return result;
}

// Interrupt handler
void intHandler(int dummy){
    pingloop=0;
}
/*--------------------------------------------------------------------*/
/*---                  Performs a DNS lookup                       ---*/
/*--------------------------------------------------------------------*/
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con){
    printf("\n[+] Resolving DNS..\n");
    struct hostent *host_entity;
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
    int i;

    if ((host_entity = gethostbyname(addr_host)) == NULL)
    {
        // No ip found for hostname
        return NULL;
    }

    //filling up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)
            host_entity->h_addr));

    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons (PORT_NO);
    (*addr_con).sin_addr.s_addr = *(long*)host_entity->h_addr;
    return ip;
}
/*--------------------------------------------------------------------*/
/*---                  make a ping request                         ---*/
/*--------------------------------------------------------------------*/
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_dom, char *ping_ip, char *rev_host){
    int ttl_val=64, msg_count=0, i, addr_len, flag=1, msg_received_count=0; // ttl = time to live

    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec=0, total_msec=0;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs);

    // set socket options at ip to TTL and value to 64,
    // change to what you want by setting ttl_val
    if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0){
        perror("\nS[-] etting socket options to TTL failed!\n");
        return;
    }
    // setting timeout of recv setting
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO,(const char*)&tv_out, sizeof tv_out);
    // send icmp packet in an infinite loop
        // flag is whether packet was sent or not
       flag=1;
       //filling packet
       bzero(&pckt, sizeof(pckt));
       pckt.hdr.type = ICMP_ECHO;
       pckt.hdr.un.echo.id = getpid(); //-1        strcpy( pckt.msg, "This is Ping!\n" );


       pckt.hdr.un.echo.sequence = msg_count++;
       pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

       usleep(PING_SLEEP_RATE);

       //send packet
       clock_gettime(CLOCK_MONOTONIC, &time_start);
       if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0){
           perror("\n[-] Packet Sending Failed!\n");
           flag=0;
       } else{
           printf("[+] Packet was send!\n");
       }
       //receive packet
       addr_len=sizeof(r_addr);
       if ( recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count>1){
           perror("\n[-] Packet receive failed!\n");
       } else{
           clock_gettime(CLOCK_MONOTONIC, &time_end);
           double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
           rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;
           // if packet was not sent, don't receive
           if(flag){
               if(!(pckt.hdr.type ==69 && pckt.hdr.code==0)){
                   printf("[-] Packet received with ICMP type %d code %d\n", pckt.hdr.type, pckt.hdr.code);
               } else {
                  printf("[+] %d bytes from %s (%s) (%s)rtt = %Lf ms.\n", PING_PKT_S, ping_dom, rev_host, ping_ip, rtt_msec);
                   msg_received_count++;
               }
           }
       }
	}

/*--------------------------------------------------------------------*/
/*--- main - look up host and start ping processes.                ---*/
/*--------------------------------------------------------------------*/
int main(){
    int sockfd;
    char *ip_addr, *reverse_hostname;
    struct sockaddr_in addr_con;
    int addrlen = sizeof(addr_con);
    char net_buf[NI_MAXHOST];
    ip_addr = dns_lookup("216.58.204.78", &addr_con);
    if(ip_addr==NULL){
        printf("\n[-] DNS lookup failed! Could not resolve hostname!\n");
        exit(0);
    }
    reverse_hostname = "google.com";
    printf("\n[+] Trying to connect to google.com IP: %s\n", ip_addr);
    printf("\n[+] Reverse Lookup domain: %s", reverse_hostname);

    //socket()
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd<0){
        perror("\n[-] Socket file descriptor not received!!\n");
        exit(0);
    }else {
        printf("\n[+] Socket file descriptor %d received\n", sockfd);
    }
    signal(SIGINT, intHandler);//catching interrupt
    //send pings continuously
    send_ping(sockfd, &addr_con, reverse_hostname,ip_addr, "google.com");

    return 0;
}

