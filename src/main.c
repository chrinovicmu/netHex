#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define RING_BUFFER_SIZE 10 
#define CACHE_LINE_SIZE 64 

#define PRINT_IP(x)\
    printf("%u.%u.%u.%u\n", \
           ((x) >> 24) & 0xFF, \
           ((x) >> 16)  & 0xFF, \
           ((x) >> 8) & 0xFF, \
           (x) & 0xF)

#define PRINT_GENERIC(x) \
    _Generic((x), \
             int: printf("%d\n", (x)), \
             unsigned int : printf("%d\n", (x)),\
             float: printf("%f\n", (x)), \
             double: printf("%lf\n", (x)), \
             char: printf("%c\n", (x)), \
             char*: printf("%s\n", (x)))

struct Packet{
    u_char *packet;
    int len;
    struct timeval time_capture; 
}
struct Ring_Buffer{
    struct Packet * packet_buffer[RING_BUFFER_SIZE];
    int head;
    int tail; 
    int count; 
    char padding[64-(sizeof(struct Packet*) + (sizeof(int)*3))]; 

}__attribute__((aligned(CACHE_LINE_SIZE));

static Ring_Buffer ring_buffer; 

int is_full(){
    return ring_buffer->count == RING_BUFFER_SIZE; 
}
int is_empty(){
    return ring_buffer->count == 0; 
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    if(is_full()){
        ring_buffer->tail = (ring_buffer->tail+1) % RING_BUFFER_SIZE; 
    }

    struct Packet packet_t;
    packet_t.packet = (u_char *)malloc(header->len);
    if(!packet_t.packet){
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    memcpy(packet_t.packet, packet, header->len);
    packet_t.len = header->len;
    packet_t.time_capture = header->ts; 

    ring_buffer->packet_buffer[ring_buffer->head] = packet_t; 
    ring_buffer->head = (ring_buffer->head +1)%RING_BUFFER_SIZE;
    ++ring_buffer->count;
    return 0;
}

void print_compiled_filter(struct bpf_program bf){
    for(int x = 0; x < bf.bf_len; ++x){
        printf("%02x", ((unsigned char *)bf.bf_insns)[x]);
        if((x + 1) % 8 == 0){
            printf("\n");
        }
    }
    printf("\n");
}
void print_hex_ascii_line(const u_char *payload, int len, int offset){

    int gap;
    const u_char *ch;

    printf("%08X", offset);

    ch = payload;

    for(int x = 0;x< len; x++){
        printf("%02X", *ch);
        ch++; 

        if(x == 7){
            printf(" ");
        }
    }

    //fill gap 
    if(len < 16){
        gap = (16 - len) *3;
        if(len <= 8){
            gap++;
        }
        while(gap--){
            printf(" ");
        }
    }

    printf("| ");


    ch = payload;
    for(int x = 0; x < len; ++x){
        if(isprint(*ch)){
            printf("%c", *ch);
        }else{
            printf(".");
        }
        ch++;
    }
    printf("\n");


}
void print_payload(const u_char *payload, int len){

    int len_rem = len;          //remaining numner of bytes to print 
    int line_width = 16;        //bytes per line
    int line_len;               // number of bytes in a current line 
    int offset = 0;             //byte offset;
    const u_char *ch = payload; // postion in payload  

    if(len < 0){
        return; 
    }

    //if data fits ome line 
    if(len <= line_width){
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    for(;;){
        //compute current line 
        line_len = (len_rem < line_width) ? len_rem : line_width;

        //print line; 
        print_hex_ascii_line(ch, line_len, offset);


        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_len;

        if(len_rem < 0){
            break; 
        }

        if(len_rem <= line_width){
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    return;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    static int count = 1; //counts packets

    const struct ether_header  *ethernet; 
    const struct ip *ip;             
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    const struct icmphdr *icmp;
    const char *payload;                    
    
    int ip_size; 
    int transport_size;
    int payload_size; 

    printf("packet number : %d\n", count);
    ++count; 

    //define ethernet header 
    ethernet = (struct ether_header *)(packet);
    ip = (struct ip *)(packet + SIZE_ETHERNET);

    ip_size = ip->ip_hl * 4; // ip header length in 4 bytes words
    if(ip_size < 20){
        printf("INVLAID IP HEADER LENGH ; %u bytes\n", ip_size);
        return;
    }

    printf("_from : %s\n", inet_ntoa(ip->ip_src));
    printf("_to : %s\n", inet_ntoa(ip->ip_dst));
    
    //PROTOCOL
    switch (ip->ip_p){

        case IPPROTO_TCP:
            printf("Protocol TCP\n");

            tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_size);
            transport_size = tcp->th_off * 4; 
            if(transport_size < 20){

                printf("Invalid Tcp Header lenght : %u bytes\n", transport_size);
                return;
            }
            payload = packet + SIZE_ETHERNET + transport_size + ip_size;
            payload_size = ntohs(ip->ip_len) - (ip_size + transport_size);
            break;

        case IPPROTO_UDP:
            printf("Protocol UDP\n"); 
            
            udp = (struct udphdr *)(packet + SIZE_ETHERNET + ip_size); 
            transport_size = sizeof(struct udphdr);

            printf("source port : %u\n", ntohs(udp->uh_sport));
            printf("destination port : %u\n", ntohs(udp->uh_dport));
            printf("UDP lenght: %u\n", ntohs(udp->uh_ulen));
            printf("UDP checksum: 0x%04x\n", ntohs(udp->uh_sum));

            payload = packet + SIZE_ETHERNET +ip_size + transport_size;
            payload_size = ntohs(udp->uh_ulen) - transport_size;
            break;

        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n"); 

            icmp = (struct icmphdr *)(packet + SIZE_ETHERNET + ip_size);
            transport_size = sizeof(struct icmphdr);

            printf("ICMP type : %u\n", icmp->type);
            printf("ICMP Code : %u\n", icmp->code);
            printf("ICMP Checksum: 0x%04x\n", ntohs(icmp->checksum));

            payload = packet + SIZE_ETHERNET + ip_size + transport_size;
            payload_size = ntohs(ip->ip_len) - (ip_size + transport_size);
            break;

        default:
            printf("Protocol: Unknown\n");
            return; 
    }
    printf("\n");

    //PAYLOAD 
    payload = packet + SIZE_ETHERNET + transport_size + ip_size;
    payload_size = ntohs(ip->ip_len) - (ip_size + transport_size);

    if(payload_size > 0){
        printf("payload %d bytes------------------------------ :\n\n", payload_size);
        print_payload(payload, payload_size);
    }
    return;

}
int main(int argc, char *argv[])
{
    
    /*
    pcap_if_t *alldevs;  

    char *device;
    char errbuff[PCAP_ERRBUF_SIZE];

    #pragma GCC diagnostic push 
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations";

    device = pcap_lookupdev(errbuff);

    #pragma GCC diagnostic pop

    if(device == NULL){
        fprintf(stderr, "couldn't find defualt device\n", errbuff);
        return(2);
    }
    */
    
    char *device; 
    pcap_if_t *alldevices;
    char errbuff[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&alldevices, errbuff) == -1){
        fprintf(stderr, "Couldn find devices %s\n", errbuff); 
        exit(EXIT_FAILURE);
    }
    if(alldevices == NULL){
        fprintf(stderr, "No devices found\n");
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    }
    device = alldevices->name; 


    pcap_t *handle;
    struct bpf_program fp; 
    char filter_exp[] = "udp";
    bpf_u_int32 mask;   
    bpf_u_int32 net;
        
    if(pcap_lookupnet(device, &net, &mask, errbuff) == -1){
        fprintf(stderr, "can't get netmask for device %s: %s\n", device, errbuff);
        net = 0;
        mask = 0; 
    }
   

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff);

    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", device, errbuff);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    
    }

    int dlt = pcap_datalink(handle);

    if(dlt != DLT_EN10MB){
        fprintf(stderr, "Device %s doesn't provide ethenet header\n", device);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE); 
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    }
 //   print_compiled_filter(fp); 

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't installl filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    }

    const struct pcap_pkthdr header; // packet header 
    const u_char *packet; // the actual packet 
    
    int result = pcap_loop(handle, 10, process_packet, NULL);
    if(result == -1){
        fprintf(stderr, "Error L %s\n", pcap_geterr(handle));
    }

    pcap_freealldevs(alldevices);
    pcap_freecode(&fp);
    pcap_close(handle);

    return EXIT_SUCCESS;
}



