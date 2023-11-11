#include "ethernet.h"
#include <netinet/ip6.h>
#include <netinet/ip.h>


/**
 * @brief fonction qui permet d'afficher le protocole IP.
 * 
 * @param protocol 
 */
void print_protocol_ip(int protocol);


/**
 * @brief fonction qui permet d'afficher les flags du protocole IP.
 * 
 * @param flags 
 */
void print_flags(u_int16_t flags);


/**
 * @brief fonction qui permet d'afficher les informations du protocole IPV4.
 * 
 * @param verbose
 * @param ip 
 * @param flags 
 */
void print_ipv4(int verbose, struct iphdr *ip,u_int16_t flags);

/**
 * @brief fonction qui permet d'afficher les informations du protocole IPV4.
 * 
 * @param verbose
 * @param ipv6

 */
void print_ipv6(int verbose, struct ip6_hdr *ipv6);



/**
 * @brief fonction qui permet d'afficher les informations du protocole IP.
 * 
 * @param packet 
 * @param verbose
 */

int ip(const unsigned char* packet, int verbose);