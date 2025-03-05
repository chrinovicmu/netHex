
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdatomic.h>
#include <pthread.h>
#include <threads.h>
#include <unistd.h>

#define SIZE_ETHERNET 14
#define RING_BUFFER_SIZE 100
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

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct Packet{
    u_char *p_packet;
    struct pcap_pkthdr *p_header; 
    int p_len;
    struct timeval p_time_capture; 
};

struct Ring_Buffer{

    struct Packet packet_buffer[RING_BUFFER_SIZE];
    _Atomic uint32_t head;
    _Atomic uint32_t tail; 
    _Atomic uint32_t count; 
    _Atomic uint8_t done;

    pthread_mutex_t mutex;
    pthread_cond_t cond_producer;
    pthread_cond_t cond_consumer; 
    char padding[CACHE_LINE_SIZE - (sizeof(int)*2 + sizeof(unsigned int))]; 

}__attribute__((aligned(CACHE_LINE_SIZE)));

static struct Ring_Buffer ring_buffer; 

int is_full(){
    return ring_buffer.count == RING_BUFFER_SIZE; 
}
int is_empty(){
    return ring_buffer.count == 0; 
}
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    pthread_mutex_lock(&ring_buffer.mutex);


    if(is_full()){

        free(ring_buffer.packet_buffer[ring_buffer.tail].p_packet);
        free(ring_buffer.packet_buffer[ring_buffer.tail].p_header);
        ring_buffer.tail = (ring_buffer.tail+1) % RING_BUFFER_SIZE; 

        if(ring_buffer.count > 0){
            --ring_buffer.count;
        }
    }

    struct Packet packet_t;
    packet_t.p_packet = (u_char *)malloc(header->len);

    if(packet_t.p_packet == NULL){
        fprintf(stderr, "Memory allocation failed\n");
        pthread_mutex_unlock(&ring_buffer.mutex);
        return;
    }
    memcpy(packet_t.p_packet, packet, header->len);

    packet_t.p_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

    if(packet_t.p_header == NULL){
        fprintf(stderr, "header memory allocation failed\n");
        free(packet_t.p_packet);
        pthread_mutex_unlock(&ring_buffer.mutex);
        return;
    }

    memcpy(packet_t.p_header, header, sizeof(struct pcap_pkthdr));
    packet_t.p_len = header->len;
    packet_t.p_time_capture = header->ts; 

    ring_buffer.packet_buffer[ring_buffer.head] = packet_t; 
    ring_buffer.head = (ring_buffer.head + 1) % RING_BUFFER_SIZE;
    ++ring_buffer.count;

    pthread_cond_signal(&ring_buffer.cond_consumer);
    pthread_mutex_unlock(&ring_buffer.mutex);
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

    int len_rem = len;          
    int line_width = 16;        
    int line_len;               
    int offset = 0;             
    const u_char *ch = payload; 

    if(len < 0){
        return; 
    }

    if(len <= line_width){
        print_hex_ascii_line(ch, len, offset);
        return;
    }    

    for(;;){
         
        line_len = (len_rem < line_width) ? len_rem : line_width;

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

void process_packet(struct Packet packet_t) {
    
    u_char* packet = (u_char *) packet_t.p_packet; 
    static int count = 1; 
    

    if (packet == NULL) {
        printf("Error: Null packet pointer\n");
        return;
    }

    const struct ether_header *ethernet; 
    const struct ip *ip;             
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    const struct icmphdr *icmp;
    const char *payload = NULL;
    
    int ip_size = 0; 
    int transport_size = 0;
    int payload_size = 0;
    
    printf("Packet number: %d\n", count);
    ++count; 

    
    if (packet_t.p_len < SIZE_ETHERNET) {
        printf("Packet too small for Ethernet header\n");
        return;
    }

    ethernet = (struct ether_header *)(packet);

    if (packet_t.p_len < SIZE_ETHERNET + sizeof(struct ip)) {
        printf("Packet too small for IP header\n");
        return;
    }

    ip = (struct ip *)(packet + SIZE_ETHERNET);
    ip_size = ip->ip_hl * 4; 


    if (ip_size < 20 || ip_size > 60) {
        printf("Invalid IP header length: %u bytes\n", ip_size);
        return;
    }

    printf("From: %s\n", inet_ntoa(ip->ip_src));
    printf("To: %s\n", inet_ntoa(ip->ip_dst));


    switch (ip->ip_p) {

        case IPPROTO_TCP:

            printf("Protocol: TCP\n");
            
            if (packet_t.p_len < SIZE_ETHERNET + ip_size + sizeof(struct tcphdr)) {
                printf("Packet too small for TCP header\n");
                return;
            }

            tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_size);
            transport_size = tcp->th_off * 4; 
            
            if (transport_size < 20 || transport_size > 60) {
                printf("Invalid TCP header length: %u bytes\n", transport_size);
                return;
            }
            
            payload = packet + SIZE_ETHERNET + ip_size + transport_size;
            payload_size = ntohs(ip->ip_len) - (ip_size + transport_size);
            break;

        case IPPROTO_UDP:

            printf("Protocol: UDP\n"); 
            
            if (packet_t.p_len < SIZE_ETHERNET + ip_size + sizeof(struct udphdr)) {
                printf("Packet too small for UDP header\n");
                return;
            }
            
            udp = (struct udphdr *)(packet + SIZE_ETHERNET + ip_size); 
            transport_size = sizeof(struct udphdr);
            
            printf("Source port: %u\n", ntohs(udp->uh_sport));
            printf("Destination port: %u\n", ntohs(udp->uh_dport));
            printf("UDP length: %u\n", ntohs(udp->uh_ulen));
            printf("UDP checksum: 0x%04x\n", ntohs(udp->uh_sum));
            
            payload = packet + SIZE_ETHERNET + ip_size + transport_size;
            payload_size = ntohs(udp->uh_ulen) - transport_size;
            

            if (payload_size < 0) {
                printf("Invalid UDP payload size\n");
                payload_size = 0;
            }
            break;

        case IPPROTO_ICMP:

            printf("Protocol: ICMP\n"); 
            
            if (packet_t.p_len < SIZE_ETHERNET + ip_size + sizeof(struct icmphdr)) {
                printf("Packet too small for ICMP header\n");
                return;
            }

            icmp = (struct icmphdr *)(packet + SIZE_ETHERNET + ip_size);
            transport_size = sizeof(struct icmphdr);
            
            printf("ICMP type: %u\n", icmp->type);
            printf("ICMP Code: %u\n", icmp->code);
            printf("ICMP Checksum: 0x%04x\n", ntohs(icmp->checksum));
            
            payload = packet + SIZE_ETHERNET + ip_size + transport_size;
            payload_size = ntohs(ip->ip_len) - (ip_size + transport_size);
            break;

        default:
            printf("Protocol: Unknown\n");
            return; 
    }


    if (payload_size > 0 && payload_size <= packet_t.p_len) {
        printf("Payload %d bytes------------------------------:\n\n", payload_size);
        print_payload(payload, payload_size);
    }
}

void *capture_packets(void *args){
    
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
    char filter_exp[] = "ip";
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
    
    int result = pcap_loop(handle, 100, packet_handler, NULL);

    if(result == -1){
        fprintf(stderr, "Error in loop %s\n", pcap_geterr(handle));
    }

    ring_buffer.done = 1;
    pthread_cond_signal(&ring_buffer.cond_consumer);

    pcap_freealldevs(alldevices);
    pcap_freecode(&fp);
    pcap_close(handle);

    return NULL;
}

void * dequeue_ring_buffer(void *args){

    struct tm local_time_buf; 
    char buffer[100];

    while(1){

        pthread_mutex_lock(&ring_buffer.mutex); 

        while(is_empty() && !ring_buffer.done){
            pthread_cond_wait(&ring_buffer.cond_consumer, &ring_buffer.mutex);
        }
        if(ring_buffer.count == 0 && ring_buffer.done){
            pthread_mutex_unlock(&ring_buffer.mutex);
            break;
        }

        struct Packet packet_t = ring_buffer.packet_buffer[ring_buffer.tail]; 
        ring_buffer.tail = (ring_buffer.tail + 1) % RING_BUFFER_SIZE;
        --ring_buffer.count;

        pthread_mutex_unlock(&ring_buffer.mutex);

        printf("\n");
        sleep(1);
        process_packet(packet_t);

        struct timeval now = packet_t.p_time_capture;
        localtime_r(&now.tv_sec, &local_time_buf);
        strftime(buffer, sizeof(buffer), "%H:%M:%S", &local_time_buf);
        printf("\nPacket Time Stamp: %s.%06ld\n", buffer, now.tv_usec);
        
        free(packet_t.p_packet);
        free(packet_t.p_header);
    }
}


int main(int argc, char *argv[])
{
    pthread_mutex_init(&ring_buffer.mutex, NULL);
    pthread_cond_init(&ring_buffer.cond_producer, NULL);
    pthread_cond_init(&ring_buffer.cond_consumer, NULL);

    pthread_t producer_thread;
    if(pthread_create(&producer_thread, NULL, capture_packets, NULL)!= 0 ){
        fprintf(stderr, "Error creating capture thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_t consumer_thread;
    if(pthread_create(&consumer_thread, NULL, dequeue_ring_buffer, NULL)!= 0){
        fprintf(stderr, "Error creating consumer thread\n");
        exit(EXIT_FAILURE);
    }

    if(pthread_join(producer_thread, NULL) != 0){
        fprintf(stderr, "Erro joining producer thread\n");
        exit(EXIT_FAILURE);
    }
    if(pthread_join(consumer_thread, NULL) != 0){
        fprintf(stderr, "Error joining consumer thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_destroy(&ring_buffer.mutex);
    pthread_cond_destroy(&ring_buffer.cond_producer); 
    pthread_cond_destroy(&ring_buffer.cond_consumer);


    return EXIT_SUCCESS;
}



