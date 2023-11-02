#include "ethernet.h"
#include "ip.h"

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_RARP_REQUEST 3
#define ARP_RARP_REPLY 4
#define ARP_InARP_REQUEST 8
#define ARP_InARP_REPLY 9



/**
 * @brief 
 * 
 * @param packet 
 * @param verbose 
 */
int arp(const unsigned char *packet, int verbose);
