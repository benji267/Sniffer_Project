#include "udp.h"


void print_udpv4(const unsigned char* packet, int verbose, const struct udphdr *udp_header){

    printf("Source Port: %d, ", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
    printf("\n");

    if(verbose>1){
        printf("Length: %d\n", ntohs(udp_header->len));
        printf("Checksum: 0x%x\n", ntohs(udp_header->check));
        printf("\n");
    }
    if(verbose>2){
        printf("Reste du paquet UDP: \n");
        for(int i=0; i<8; i++){
            printf("%x ", packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + i]);
        }
        printf("\n");
    }
} 

void print_udpv6(const unsigned char* packet, int verbose, const struct udphdr *udp_header){

    printf("Source Port: %d, ", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
    printf("\n");

    if(verbose>1){
        printf("Length: %d\n", ntohs(udp_header->len));
        printf("Checksum: 0x%x\n", ntohs(udp_header->check));
        printf("\n");
    }
    if(verbose>2){
        printf("Reste du paquet UDP: \n");
        for(int i=0; i<8; i++){
            printf("%x ", packet[sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + i]);
        }
        printf("\n");
    }
}

void udp(const unsigned char* packet, int verbose, int type){

    switch(type){
        case 4:
            const struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            printf("Protocol UDPV4: \n");
            print_udpv4(packet, verbose, udp_header);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        case 6:
            udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            printf("Protocol UDPV6: \n");
            print_udpv6(packet, verbose, udp_header);
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