#include "arp.h"

int arp(const unsigned char *packet,int verbose){
    printf("Protocol: ARP\n");
    //struct arphdr *arp = (struct arphdr*)(packet + sizeof(struct ethhdr));
    return 1;
}