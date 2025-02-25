
/*
 * This code is based on the work of Tim Carstens, who developed the original sniffer.c.
 * 
 * The original code was distributed under the following license:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions, and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define PRINT_IP(x)\
    printf("%u.%u.%u.%u\n", \
           ((x) >> 24) & 0xFF, \
           ((x) >> 16)  & 0xFF, \
           ((x) >> 8) & 0xFF, \
           (x) & 0xFF

#define PRINT_GENERIC(x) \
    _Generic((x), \
             int: printf("%d\n", (x)), \
             unsigned int : printf("%d\n", (x)),\
             float: printf("%f\n", (x)), \
             double: printf("%lf\n", (x)), \
             char: printf("%c\n", (x)), \
             char*: printf("%s\n", (x)))

void print_compiled_filter(struct bpf_program bf){
    for(int x = 0; x < bf.bf_len; ++x){
        printf("%02x", ((unsigned char *)bf.bf_insns)[x]);
        if((x + 1) % 8 == 0){
            printf("%s\n");
        }
    }
    printf("\n");
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    static int count = 1; //counts packets

    const struct sniff_ethernet *ethernetl // ehernet header
    const struct sniff_ip *ipl;             // ip header 
    const struct sniff_tcp *tcp            // the tcp header 
    const char *payload                     //packet pay load 
    
    int ip_size; 
    int tcp_size;
    int payload_size; 

    printf("packet number : d%", count);
    ++count; 

    //define ethernet header 
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip)(packet + SIZE_ETHERNET);

    ip_size = IP_HL(ip)* 4;
    if(ip_size < 20){
        printf("INVLAID IP HEADER LENGH ; %u bytes\n", ip_size);
        return;
    }

    printf("from : %s\n", inet_ntoa(ip->ip_src));
    printf("from : %s\n", inet_ntoa(ip->ip_dst));
    
    //PROTOCOL
    switch (ip->ip_p){
        case IPPROTO_TCP:
            printf("Protocol TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Protocol UDP\n"); 
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n"); 
            break;
        case IPPROTO_IP:
            printf("Protocol: IP\n"); 
            break;
        default:
            printf("Protocol: Unknown\n");
            return; 
    }

    tcp = (struct_tcp*)(packet + SIZE_ETHERNET + ip_size);
    tcp_size = TH_OFF(tcp)*4;
    if(tcp_size < 20){
        printf("invalid tcp header lenght : %u bytes\n", tcp_size);
        return;
    }

    payload = (u_char*)packet( + SIZE_ETHERNET + tcp_size + ip_size);
    payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

    if(payload_size > 0){
        printf("payload %d bytees :\n", payload_size);
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
        return 2; 
    }
    if(alldevices == NULL){
        fprintf(stderr, "No devices found\n");
        return(2);
    }
    device = alldevices->name; 


    pcap_t *handle;
    struct bpf_program fp ; // compiled filer expression
    char filter_exp[] = "tcp  port 80";
    bpf_u_int32 mask;   //the net mask 
    bpf_u_int32 net;    // ip of our sniffing device 
        
    if(pcap_lookupnet(device, &net, &mask, errbuff) == -1){
        fprintf(stderr, "can't get netmask for device %s: %s\n", device, errbuff);
        net = 0;
        mask = 0; 
    }
   

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff);

    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", device, errbuff);
        pcap_freealldevs(alldevices);
        return(2);
    }

    int dlt = pcap_datalink(handle);

    if(dlt != DLT_EN10MB){
        fprintf(stderr, "Device %s doesn't provide ethenet header\n", device);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        return(2);
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        return(2);
    }
  //  print_compiled_filter(fp); 

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't installl filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevices);
        return(2);
    }

    struct pcap_pkthdr header; // packet header 
    const u_char *packet; // the actual packet 
    
    packet = pcap_next(handle, &header);
    if(packet == NULL){
        fprintf(stderr, "No packet captured\n");
        pcap_close(handle);
    }
    printf("packet len : [%d]\n", header.len);

    pcap_freealldevs(alldevices);
    pcap_freecode(&fp);
    pcap_close(handle);

    return EXIT_SUCCESS;
}



