#include "ethernet.h"


void print_type_ethernet(int type){
    switch(type){
        case ETHERTYPE_IPV4_Custom:
            printf("IPV4 ");
            break;
        case ETHERTYPE_IPV6_Custom:
            printf("IPV6 ");
            break;
        case ETHERTYPE_ARP_Custom:
            printf("ARP ");
            break;
        default:
            printf("Unknown ");
            break;
    }
}

int ethernet(const unsigned char *packet, int verbose){
    struct ether_header *ethernet;
    ethernet = (struct ether_header *) packet;
    printf("Protocole Ethernet: ");
    printf("Adresse MAC Source: %02x:%02x:%02x:%02x:%02x:%02x -> ", 
        ethernet->ether_shost[0], ethernet->ether_shost[1], 
        ethernet->ether_shost[2], ethernet->ether_shost[3], 
        ethernet->ether_shost[4], ethernet->ether_shost[5]);
    printf("Adresse MAC Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        ethernet->ether_dhost[0], ethernet->ether_dhost[1], 
        ethernet->ether_dhost[2], ethernet->ether_dhost[3], 
        ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

    printf("\n");
        
    if(verbose>1){
        printf("Type: ");
        print_type_ethernet(ntohs(ethernet->ether_type));
        printf("\n");
    }

    if(verbose>2){
        int header_length = sizeof(struct ether_header);
        printf("Payload: ");
        int i;
        for(i=0;i<header_length;i++){
            printf("%02x ", packet[i]);
        }
        printf("\n");
    }
    for(int i=0;i<6;i++){
        printf("\n");
    }

    return ntohs(ethernet->ether_type);
}