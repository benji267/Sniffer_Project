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

int print_udpv4(const unsigned char* packet, int verbose, const struct udphdr *udp_header){
    
    printf("Source Port: %d, ", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
    printf("\n");
    int application_protocol = udp_application(ntohs(udp_header->source), ntohs(udp_header->dest));

    if(verbose>1){
        printf("Length: %d\n", ntohs(udp_header->len));
        printf("Checksum: 0x%x\n", ntohs(udp_header->check));
        printf("\n");
    }
    if(verbose>2){
        udp_print_application(ntohs(udp_header->source), ntohs(udp_header->dest));
        printf("\n");
    }
    return application_protocol;
} 

int print_udpv6(const unsigned char* packet, int verbose, const struct udphdr *udp_header){

    printf("Source Port: %d, ", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
    printf("\n");
    int application_protocol = udp_application(ntohs(udp_header->source), ntohs(udp_header->dest));
    if(verbose>1){
        printf("Length: %d\n", ntohs(udp_header->len));
        printf("Checksum: 0x%x\n", ntohs(udp_header->check));
        printf("\n");
    }
    if(verbose>2){
        udp_print_application(ntohs(udp_header->source), ntohs(udp_header->dest));
        printf("\n");
    }
    return application_protocol;
}

int udp(const unsigned char* packet, int verbose, int type){

    switch(type){
        case 4:
            const struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            printf("Protocol UDPV4: \n");
            int app=print_udpv4(packet, verbose, udp_header);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            return app;
            break;
        case 6:
            udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            printf("Protocol UDPV6: \n");
            int appv6=print_udpv6(packet, verbose, udp_header);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            return appv6;
            break;
        default:
            printf("Unknown\n");
            break;
    }
    return -1;
}