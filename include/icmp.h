#include "ethernet.h"
#include "ip.h"
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <stdbool.h>

/**
 * @brief Displays the ICMPV4 protocol type.
 * 
 * @param type
 */
void print_icmpv4_type(int type);


/**
 * @brief Displays the ICMPV6 protocol type.
 * 
 * @param type
 */
void print_icmpv6_type(int type);

/**
 * @brief Displays the information of the ICMPV4 layer.
 * 
 * @param packet
 * @param icmp_header
 * @param verbose
 */
void print_icmpv4(const unsigned char* packet, struct icmphdr *icmp_header, int verbose);

/**
 * @brief Displays the information of the ICMPV6 layer.
 * 
 * @param packet
 * @param icmp6_header
 * @param verbose
 */
void print_icmpv6(const unsigned char* packet, struct icmp6_hdr *icmp6_header, int verbose);


/**
 * @brief Displays the information of the ICMP layer.
 * 
 * @param packet 
 * @param verbose 
 * @param type  
 */
void icmp(const unsigned char* packet, int verbose, int type);
