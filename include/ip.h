#include "ethernet.h"
#include <netinet/ip6.h>
#include <netinet/ip.h>


/**
 * @brief function that displays the following protocol.
 * 
 * @param protocol 
 */
void print_protocol_ip(int protocol);


/**
 * @brief function that displays the flags of the IPV4 protocol.
 * 
 * @param flags 
 * @param verbose
 */
void print_flags(u_int16_t flags,int verbose);


/**
 * @brief function that displays the IPV4 protocol information.
 * 
 * @param verbose
 * @param ip 
 * @param flags 
 */
void print_ipv4(int verbose, struct iphdr *ip,u_int16_t flags);

/**
 * @brief function that displays the IPV6 protocol information.
 * 
 * @param verbose
 * @param ipv6

 */
void print_ipv6(int verbose, struct ip6_hdr *ipv6);



/**
 * @brief function that displays the IPV4 or IPV6 protocol information.
 * 
 * @param packet 
 * @param verbose
 */

int ip(const unsigned char* packet, int verbose);