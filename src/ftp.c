#include "ftp.h"

void ftp(const unsigned char* packet, int verbose, int type, uint16_t *option_length){
    printf("File Transfer Protocol\n");
    switch(type){
        case 4:
            packet += sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + *option_length;
            break;
        
        case 6:
            packet += sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
            break;
    }
    if(verbose==2){
        
    }
    return;
}
