#include "udp.h"



void print_udp(const unsigned char* packet, int verbose, struct udphdr *udp_header){
} 


void udp(const unsigned char* packet, int verbose, int type)

    const struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    switch(type){
        case 4:

    }