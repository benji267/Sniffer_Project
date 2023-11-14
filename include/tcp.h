#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>


#define LENMAXSEG 4
#define LENWINDOW 3
#define LEN_SACK_PERMITTED 2
#define LEN_TIMESTAMP 10




/**
 * @brief Print TCPV4 option.
 * 
 * @param packet
 * @param offset
 */
void print_optionv4(const unsigned char *packet,uint8_t offset);


/**
 * @brief Print TCPV6 option.
 * 
 * @param packet
 * @param offset
 */
void print_optionv6(const unsigned char *packet,uint8_t offset);


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