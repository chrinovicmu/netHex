#include <netinet/in.h>
#include <pcap/pcap.h>
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
#include <unistd.h>
#include <stdalign.h>

#define SIZE_ETHERNET 14

/*maximum netork transmisson unit */
#define NETWORK_MTU 1518 

/*maximum buffer size and packets to capture*/ 
#define RING_BUFFER_SIZE 100

/*architecure specific max cache line size for padding */  
#define CACHE_LINE_SIZE 64

/*padding for packet structure*/
#define PACKET_PADDING (CACHE_LINE_SIZE - ((NETWORK_MTU + sizeof(struct pcap_pkthdr)\
    + sizeof(int) + sizeof(struct timeval)) % CACHE_LINE_SIZE))


/*ignore */ 
#define PRINT_IP(x)\
    printf("%u.%u.%u.%u\n", \
           ((x) >> 24) & 0xFF, \
           ((x) >> 16)  & 0xFF, \
           ((x) >> 8) & 0xFF, \
           (x) & 0xFF)

#define PRINT_GENERIC(x) \
    _Generic((x), \
             int: printf("%d\n", (x)), \
             unsigned int : printf("%d\n", (x)),\
             float: printf("%f\n", (x)), \
             double: printf("%lf\n", (x)), \
             char: printf("%c\n", (x)), \
             char*: printf("%s\n", (x)))

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct packet_t{

    u_char p_packet[NETWORK_MTU];
    struct pcap_pkthdr p_header; 
    int p_len;
    struct timeval p_time_capture;
    char padding[PACKET_PADDING];

}__attribute__((aligned(CACHE_LINE_SIZE)));

struct ring_buffer_t{

    struct packet_t packet_buffer[RING_BUFFER_SIZE];

    alignas(CACHE_LINE_SIZE) _Atomic uint32_t head;
    alignas(CACHE_LINE_SIZE) _Atomic uint32_t tail; 
    alignas(CACHE_LINE_SIZE) _Atomic uint32_t count; 
    alignas(CACHE_LINE_SIZE) _Atomic uint8_t done;

    pthread_mutex_t mutex;
    pthread_cond_t cond_producer;
    pthread_cond_t cond_consumer; 
    char padding[CACHE_LINE_SIZE - (sizeof(int)*2 + sizeof(unsigned int))]; 

}__attribute__((aligned(CACHE_LINE_SIZE)));

static struct ring_buffer_t ring_buffer; 

int is_rb_full(void){
    return ring_buffer.count == RING_BUFFER_SIZE; 
}
int is_rb_empty(void){
    return ring_buffer.count == 0; 
}


/*this is the callback function for the packet capturing 
 *caputures individual packet and temporary store in ring buffer before processing 
 * */

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    pthread_mutex_lock(&ring_buffer.mutex);


    if(is_rb_full())
    {
        ring_buffer.tail = (ring_buffer.tail+1) % RING_BUFFER_SIZE; 

        if(ring_buffer.count > 0){
            --ring_buffer.count;
        }
    }

    struct packet_t *pk;
    pk = &ring_buffer.packet_buffer[ring_buffer.head];

    if(header->len > NETWORK_MTU){
        fprintf(stderr, "packet too large! discarded\n");
        pthread_mutex_unlock(&ring_buffer.mutex);
        return;
    }

    memcpy(pk->p_packet, packet, header->len);
    memcpy(&pk->p_header, header, sizeof(struct pcap_pkthdr));

    pk->p_len = header->len;
    pk->p_time_capture = header->ts; 

    ring_buffer.head = (ring_buffer.head + 1) % RING_BUFFER_SIZE;
    ++ring_buffer.count;

    pthread_cond_signal(&ring_buffer.cond_consumer);
    pthread_mutex_unlock(&ring_buffer.mutex);
}


/*ignore : test function for debugging*/ 

void print_compiled_filter(struct bpf_program bf)
{

    for(int x = 0; x < bf.bf_len; ++x)
    {
        printf("%02x", ((unsigned char *)bf.bf_insns)[x]);

        if((x + 1) % 8 == 0){
            printf("\n");
        }
    }
    printf("\n");
}


/* converts the hex packet payload representation to ascii, for human readability */

void print_hex_ascii_line(const u_char *payload, int len, int offset) 
{
    char buffer[80]; // Fixed size for one 16-byte line
    const u_char *ch = payload;
    int bytes_remaining = len;
    int current_offset = offset;

    if (len < 0) return; 

    /* Process payload in 16-byte chunks */ 

    while (bytes_remaining > 0) 
    {
        int chunk_len = (bytes_remaining > 16) ? 16 : bytes_remaining;
        int pos = 0;

        /* Write offset */ 

        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%08X ", current_offset);

        /* Hexadecimal section */ 

        for (int x = 0; x < 16; x++) {
            if (x < chunk_len) {
                pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%02X ", ch[x]);
            } else {
                pos += snprintf(buffer + pos, sizeof(buffer) - pos, "   ");
            }
            if (x == 7 && pos < sizeof(buffer)) {
                buffer[pos++] = ' '; 
            }
        }
        
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "| ");

        /* ASCII section */

        for (int x = 0; x < chunk_len; x++) 
        {
            if (pos < sizeof(buffer) - 1)
            {
                buffer[pos++] = isprint(ch[x]) ? ch[x] : '.';
            }
        }

        if (pos < sizeof(buffer) - 1) buffer[pos++] = '\n';
        if (pos < sizeof(buffer)) buffer[pos] = '\0';


        printf("%s", buffer);

        ch += chunk_len;
        bytes_remaining -= chunk_len;
        current_offset += chunk_len;
    }
}
/*main function to print payload info which calls print_hex_ascii */ 

void print_payload(const u_char *payload, int len)
{

    int len_rem = len;          
    int line_width = 16;        
    int line_len;               
    int offset = 0;             
    const u_char *ch = payload; 

    if(len < 0){
        return; 
    }

    if(len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }    

    for(;;)
    {
         
        line_len = (len_rem < line_width) ? len_rem : line_width;

        print_hex_ascii_line(ch, line_len, offset);

        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_len;

        if(len_rem < 0){
            break; 
        }

        if(len_rem <= line_width)
        {
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    return;
}


void process_packet(struct packet_t *pk)
{
    
    u_char* packet = (u_char *) pk->p_packet; 
    static int count = 1; 
    

    if (packet == NULL) 
    {
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
    
    printf("packet_t number: %d\n", count);
    ++count; 

    
    if (pk->p_len < SIZE_ETHERNET)
    {
        printf("packet_t too small for Ethernet header\n");
        return;
    }

    ethernet = (struct ether_header *)(packet);

    if (pk->p_len < SIZE_ETHERNET + sizeof(struct ip)) 
    {
        printf("packet_t too small for IP header\n");
        return;
    }

    ip = (struct ip *)(packet + SIZE_ETHERNET);
    ip_size = ip->ip_hl * 4; 


    if (ip_size < 20 || ip_size > 60 || SIZE_ETHERNET + ip_size > pk->p_len) 
    {
        printf("Invalid IP header length: %u bytes\n", ip_size);
        return;
    }

    printf("From: %s\n", inet_ntoa(ip->ip_src));
    printf("To: %s\n", inet_ntoa(ip->ip_dst));


    switch (ip->ip_p)
    {

        case IPPROTO_TCP:

            printf("Protocol: TCP\n");
            
            if (pk->p_len < SIZE_ETHERNET + ip_size + sizeof(struct tcphdr))
            {
                printf("packet_t too small for TCP header\n");
                return;
            }

            tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_size);
            transport_size = tcp->th_off * 4; 
            
            if (transport_size < 20 || transport_size > 60)
            {
                printf("Invalid TCP header length: %u bytes\n", transport_size);
                return;
            }
            
            payload = packet + SIZE_ETHERNET + ip_size + transport_size;
            payload_size = ntohs(ip->ip_len) - (ip_size + transport_size);
            break;

        case IPPROTO_UDP:

            printf("Protocol: UDP\n"); 
            
            if (pk->p_len < SIZE_ETHERNET + ip_size + sizeof(struct udphdr)) 
            {
                printf("packet_t too small for UDP header\n");
                return;
            }
            
            udp = (struct udphdr *)(packet + SIZE_ETHERNET + ip_size); 
            transport_size = sizeof(struct udphdr);
            
            printf("Source port: %u\n", ntohs(udp->uh_sport));
            printf("Destination port: %u\n", ntohs(udp->uh_dport));
            printf("UDP length: %u\n", ntohs(udp->uh_ulen));
            printf("UDP checksum: 0x%04x\n", ntohs(udp->uh_sum));
            
            payload = packet + SIZE_ETHERNET + ip_size + transport_size;
            int udp_len = ntohs(udp->uh_ulen);

            if(udp_len < transport_size || SIZE_ETHERNET + ip_size + udp_len > pk->p_len)
            {
                printf("invalid udp length field\n");
                return;
            }
            payload_size = ntohs(udp->uh_ulen) - transport_size;

            if (payload_size < 0) {
                printf("Invalid UDP payload size\n");
                payload_size = 0;
            }
            break;

        case IPPROTO_ICMP:

            printf("Protocol: ICMP\n"); 
            
            if (pk->p_len < SIZE_ETHERNET + ip_size + sizeof(struct icmphdr))
            {
                printf("packet_t too small for ICMP header\n");
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


    if (payload_size > 0 && payload_size <= pk->p_len)
    {
        printf("Payload size %d bytes\n", payload_size);
        print_payload(payload, payload_size);
    }
}


/** Ring Buffer Producer Thread Function which captures incomming packets */

void *capture_packets(void *arg)
{
    char *filter_exp = (char*)arg;
    char *device; 
    pcap_if_t *alldevices;
    char errbuff[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&alldevices, errbuff) == -1)
    {
        fprintf(stderr, "Couldn find devices %s\n", errbuff); 
        exit(EXIT_FAILURE);
    }

    if(alldevices == NULL)
    {
        fprintf(stderr, "No devices found\n");
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    }
    device = alldevices->name; 


    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;   
    bpf_u_int32 net;
        
    if(pcap_lookupnet(device, &net, &mask, errbuff) == -1)
    {
        fprintf(stderr, "can't get netmask for device %s: %s\n", device, errbuff);
        net = 0;
        mask = 0; 
    } 

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff);

    if(handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", device, errbuff);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    }

    int dlt = pcap_datalink(handle);

    if(dlt != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide ethenet header\n", device);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE); 
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    }

    /*
    print_compiled_filter(fp); 
    */ 

    if(pcap_setfilter(handle, &fp) == -1)
    {

        fprintf(stderr, "Couldn't installl filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        exit(EXIT_FAILURE);
    }

    const struct pcap_pkthdr header; // packet header 
    const u_char *packet; // the actual packet 
    
    int result = pcap_loop(handle, RING_BUFFER_SIZE, packet_handler, NULL);

    if(result == -1)
    {
        fprintf(stderr, "Error in loop %s\n", pcap_geterr(handle));
    }

    ring_buffer.done = 1;
    pthread_cond_signal(&ring_buffer.cond_consumer);

    pcap_freealldevs(alldevices);
    pcap_freecode(&fp);
    pcap_close(handle);

    return NULL;
}


/* Ring Buffer Consumer Thread Function which processes individual packets in the buffer */

void * dequeue_ring_buffer(void *args)
{

    struct tm local_time_buf; 
    char buffer[100];

    while(1)
    {
        pthread_mutex_lock(&ring_buffer.mutex); 

        while(is_rb_empty() && !ring_buffer.done)
        {
            pthread_cond_wait(&ring_buffer.cond_consumer, &ring_buffer.mutex);
        }

        if(ring_buffer.count == 0 && ring_buffer.done)
        {
            pthread_mutex_unlock(&ring_buffer.mutex);
            break;
        }

        struct packet_t *pk = &ring_buffer.packet_buffer[ring_buffer.tail]; 
        ring_buffer.tail = (ring_buffer.tail + 1) % RING_BUFFER_SIZE;
        --ring_buffer.count;

        pthread_mutex_unlock(&ring_buffer.mutex);

        printf("\n");
       // sleep(1);
        printf("PACKET SIZE : %u bytes\n", pk->p_len);
        process_packet(pk);

        struct timeval now = pk->p_time_capture;
        localtime_r(&now.tv_sec, &local_time_buf);
        strftime(buffer, sizeof(buffer), "%H:%M:%S", &local_time_buf);
        printf("\npacket_t Time Stamp: %s.%06ld\n", buffer, now.tv_usec);

        printf("\n-------------------------------------------------------------------\n");
        
    }
    return NULL; 
}


int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        printf("Error: incude protocol for filtering , e.g 'udp', 'tcp\n");
        printf("Usage: make -PF <filter>\n");
        exit(EXIT_FAILURE);
    }
    pthread_mutex_init(&ring_buffer.mutex, NULL);
    pthread_cond_init(&ring_buffer.cond_producer, NULL);
    pthread_cond_init(&ring_buffer.cond_consumer, NULL);

    pthread_t producer_thread;
    if(pthread_create(&producer_thread, NULL, capture_packets, (void *)argv[1])!= 0 )
    {
        fprintf(stderr, "Error creating capture thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_t consumer_thread;
    if(pthread_create(&consumer_thread, NULL, dequeue_ring_buffer, NULL)!= 0)
    {
        fprintf(stderr, "Error creating consumer thread\n");
        exit(EXIT_FAILURE);
    }

    if(pthread_join(producer_thread, NULL) != 0)
    {
        fprintf(stderr, "Erro joining producer thread\n");
        exit(EXIT_FAILURE);
    }
    if(pthread_join(consumer_thread, NULL) != 0)
    {
        fprintf(stderr, "Error joining consumer thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_destroy(&ring_buffer.mutex);
    pthread_cond_destroy(&ring_buffer.cond_producer); 
    pthread_cond_destroy(&ring_buffer.cond_consumer);


    return EXIT_SUCCESS;
}



