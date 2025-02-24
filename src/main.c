
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define PRINT_GENERIC(x) \
    _Generic((x), \
             int: printf("%d\n", (x)), \
             unsigned int : printf("%d\n", (x)),\
             float: printf("%f\n", (x)), \
             double: printf("%lf\n", (x)), \
             char: printf("%c\n", (x)), \
             char*: printf("%s\n", (x)))



int main(int argc, char *argv[])
{
    /*
    pcap_if_t *alldevs;  
    */
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

    pcap_t *handle;
    struct bpf_program fp ; // compiled filer expression
    char filter_exp[] = "port 23";
    bpf_u_int32 mask;   //the net mask 
    bpf_u_int32 net;    // ip of our sniffing device 
        
    if(pcap_lookupnet(device, &net, &mask, errbuff) == -1){
        fprintf(stderr, "can't get netmask for device %s: %s\n", device, errbuff);
        net = 0;
        mask = 0; 
    }
    
    PRINT_GENERIC(net); 
    PRINT_GENERIC(mask);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff);
    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", device, errbuff);
    }

    int dlt = pcap_datalink(handle);
    if(dlt != DLT_EN10MBI){
        fprintf(stderr, "Device %s doesn't provide ethenet header\n", dev);
        return(2);
    }

    if(pcap_compile(handle, &fp, filter_exp, 00, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't installl filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }






    return EXIT_SUCCESS;
}



