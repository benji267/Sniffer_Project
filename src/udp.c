#include "udp.h"



uint16_t calculate_udp_checksum(const unsigned char* packet, size_t len) {
    const struct udphdr* udp_header = (struct udphdr*)packet;

    uint32_t sum = 0;
    size_t i;

    for (i = 0; i < sizeof(struct udphdr) / 2; ++i) {
        sum += ntohs(((uint16_t*)udp_header)[i]);
    }

    // Si la longueur du message est impaire, ajouter le dernier octet
    if (len % 2 == 1) {
        sum += ntohs((uint16_t)(packet[len - 1]) << 8);
    }

    // Ajouter le pseudo-en-tête
    sum += ntohs((uint16_t)0x0800);  // IPv4 protocol
    sum += ntohs((uint16_t)(udp_header->len));

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}


void print_udpv4(const unsigned char* packet, int verbose, const struct udphdr *udp_header){

    printf("Source Port: %d, ", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
    printf("\n");

    if(verbose>1){
        printf("Length: %d\n", ntohs(udp_header->len));
        printf("Checksum: 0x%x\n", ntohs(udp_header->check));

        uint16_t calculated_checksum = calculate_udp_checksum(packet + sizeof(struct ether_header) + sizeof(struct iphdr), ntohs(udp_header->len));
        printf("Calculated Checksum: 0x%x\n", calculated_checksum);
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