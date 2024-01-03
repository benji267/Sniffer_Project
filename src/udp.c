#include "udp.h"

int udp_application(int source, int destination){
    if(source==DNS || destination==DNS){
        return DNS;
    }
    else if(source==BOOTP || destination==BOOTP){
        return BOOTP;
    }
    else if(source==DHCP || destination==DHCP){
        return DHCP;
    }
    else{
        return -1;
    }
}



void udp_print_application(int source, int destination){
    if(source==DNS || destination==DNS){
        printf("Following application: DNS\n");
    }
    else if(source==BOOTP || destination==BOOTP){
        printf("Following application: BOOTP/DHCP\n");
    }
    else if(source==DHCP || destination==DHCP){
        printf("Following application: BOOTP/DHCP\n");
    }
    else{
        printf("Unknown\n");
    }
    return ;
}

int print_udp(const unsigned char* packet, int verbose, const struct udphdr *udp_header){
    
    printf("%d, ", ntohs(udp_header->source));
    printf(" Dst Port: %d\n", ntohs(udp_header->dest));
    int application_protocol = udp_application(ntohs(udp_header->source), ntohs(udp_header->dest));

    if(verbose>1){
        printf(" |- Source Port: %d\n", ntohs(udp_header->source));
        printf(" |- Destination Port: %d\n", ntohs(udp_header->dest));
        printf(" |- Length: %d\n", ntohs(udp_header->len));
        printf(" |- Checksum: 0x%x\n", ntohs(udp_header->check));
        printf(" |- UDP payload: (%ld bytes)\n", ntohs(udp_header->len)-sizeof(struct udphdr));
    }
    if(verbose>2){
        printf("     |- ");
        udp_print_application(ntohs(udp_header->source), ntohs(udp_header->dest));
        printf("\n");
    }
    return application_protocol;
}

// Principal function which calls the other functions and parse the packet for the UDP layer.
int udp(const unsigned char* packet, int verbose, int type){
    printf("User Datagram Protocol, Src Port: ");
    int app;
    switch(type){
        case 4:
            const struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            app=print_udp(packet, verbose, udp_header);
            break;
        case 6:
            udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            app=print_udp(packet, verbose, udp_header);
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("\n");
    return app;
}