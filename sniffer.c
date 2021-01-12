#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>    //Provides declarations for icmp header
#include<netinet/ip.h>    //Provides declarations for ip header

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

void process_ip_packet(const u_char *, int);

void print_ip_packet(const u_char *, int);

void print_icmp_packet(const u_char *, int);

void PrintData(const u_char *, int);

struct sockaddr_in source, dest;
struct bpf_program fp;
char filter_exp[] = "ip proto icmp";
bpf_u_int32 net;
int icmp = 0, i, j;

int main() {
    pcap_if_t *alldevsp, *device;
    pcap_t *handle; //Handle of the device that shall be sniffed

    char errbuf[100], *devname, devs[100][100];
    int count = 1, n;

    //First get the list of available devices
    printf("Finding available devices ... ");
    if (pcap_findalldevs(&alldevsp, errbuf)) {
        printf("Error finding devices : %s", errbuf);
        exit(1);
    }
    printf("Done");

    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for (device = alldevsp; device != NULL; device = device->next) {
        printf("%d. %s - %s\n", count, device->name, device->description);
        if (device->name != NULL) {
            strcpy(devs[count], device->name);
        }
        count++;
    }

    //Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d", &n);
    devname = devs[n];

    //Open the device for sniffing
    printf("Opening device %s for sniffing ... ", devname);
    handle = pcap_open_live(devname, 65536, 1, 0, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s : %s\n", devname, errbuf);
        exit(1);
    }
    printf("Done\n");

    // add filter
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    //Put the device in sniff loop
    pcap_loop(handle, -1, process_packet, NULL);
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
    int size = header->len;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    ++icmp;
    print_icmp_packet(buffer, size);
    printf("ICMP : %d \r", icmp);
}

void print_ip_header(const u_char *Buffer, int Size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *) (Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("\nIP Header:\n");
    printf("   -Source IP        : %s\n", inet_ntoa(source.sin_addr));
    printf("   -Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void print_icmp_packet(const u_char *Buffer, int Size) {
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *) (Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    printf("\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer, Size);


    printf("\nICMP Header:\n");
    printf("   -Type : %d\n", (unsigned int) (icmph->type));

    printf("   -Code : %d\n", (unsigned int) (icmph->code));

    printf("\n###########################################################");
}
