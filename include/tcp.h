#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <getopt.h>





/**
 * @brief Print TCP option.
 * 
 * @param packet
 */
void print_option(const unsigned char *packet);


/**
 * @brief Print TCPV4 header.
 * 
 * @param packet 
 * @param verbose 
 * @param tcp_header 
 */
void print_tcpv4(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header);


/**
 * @brief Print TCPV6 header.
 * 
 * @param packet 
 * @param verbose 
 * @param tcp_header 
 */
void print_tcpv6(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header);




/**
 * @brief Display TCP header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 */
void tcp(const unsigned char* packet, int verbose, int type);