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
    char filter_exp[] = "tcp port 80";
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



