#include "udp.h"



void print_udpv4(const unsigned char* packet, int verbose, const struct udphdr *udp_header){

    printf("Source Port: %d, ", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));

    if(verbose>1){
        printf("Length: %d\n", ntohs(udp_header->len));
        printf("Checksum: %x\n", ntohs(udp_header->check));
    }
} 


void udp(const unsigned char* packet, int verbose, int type){

    const struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    switch(type){
        case 4:
            printf("Protocol UDPV4: \n");
            print_udpv4(packet, verbose, udp_header);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        default:
            printf("Unknown\n");
            break;
    }
    return ;
}