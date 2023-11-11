#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include <netinet/udp.h>


/**
 * @brief Display UDPV4 header.
 * 
 * @param packet
 * @param verbose
 * @param udp_header
 */
void print_udpv4(const unsigned char* packet, int verbose, const struct udphdr *udp_header);


/**
 * @brief Display UDP header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 */
void udp(const unsigned char* packet, int verbose, int type);