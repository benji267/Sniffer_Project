#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include <netinet/udp.h>




/**
 * @brief Display UDP header.
 * 
 * @param packet 
 * @param verbose 
 * @param udp_header 
 */

void print_udp(const unsigned char* packet, int verbose, struct udphdr *udp_header);