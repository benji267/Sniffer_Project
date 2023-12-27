#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include <netinet/udp.h>


#define DNS 53
#define BOOTP 68
#define DHCP 67



/**
 * @brief Return the application protocol used by the packet.
 * 
 * @param source 
 * @param destination 
 * @return int 
 */
int udp_application(int source, int destination);

/**
 * @brief Display the application protocol used by the packet.
 * 
 * @param source 
 * @param destination 
 */
void udp_print_application(int source, int destination);

/**
 * @brief Display UDPV4 header.
 * 
 * @param packet
 * @param verbose
 * @param udp_header
 */
int print_udpv4(const unsigned char* packet, int verbose, const struct udphdr *udp_header);

/**
 * @brief Display UDPV6 header.
 * 
 * @param packet
 * @param verbose
 * @param udp_header
 */
int print_udpv6(const unsigned char* packet, int verbose, const struct udphdr *udp_header);


/**
 * @brief Display UDP header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 */
int udp(const unsigned char* packet, int verbose, int type);