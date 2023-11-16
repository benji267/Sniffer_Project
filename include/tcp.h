#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>


#define LENMAXSEG 4
#define LENWINDOW 3
#define LEN_SACK_PERMITTED 2
#define LEN_TIMESTAMP 10


#define TELNET 23


/**
 * @brief Print application.
 * 
 * @param source 
 * @param destination 
 * @return the numeric value of the application.
 */
int print_application(int source, int destination);


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
int print_tcpv4(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header);


/**
 * @brief Print TCPV6 header.
 * 
 * @param packet 
 * @param verbose 
 * @param tcp_header 
 */
int print_tcpv6(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header);




/**
 * @brief Display TCP header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 */
int tcp(const unsigned char* packet, int verbose, int type);