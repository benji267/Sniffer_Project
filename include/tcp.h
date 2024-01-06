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
#define HTTP 80
#define POP3 110
#define IMAP 143
#define DNS 53
#define SMTP 25
#define FTP 21


/**
 * @brief Print application.
 * 
 * @param source 
 * @param destination 
 */
void print_application(int source, int destination);


/**
 * @brief Get the numeric value of the application.
 * 
 * @param source
 * @param destination
 * 
 */
int app_value(int source, int destination);

/**
 * 
 * @brief Print TCPV4 option.
 * 
 * @param packet
 * @param offset
 * @param verbose
 * @param version
 */
void print_optionv4(const unsigned char *packet,uint8_t offset, int verbose, int version);


/**
 * @brief Print TCPV6 option.
 * 
 * @param packet
 * @param offset
 * @param verbose
 */
void print_optionv6(const unsigned char *packet,uint8_t offset, int verbose);


/**
 * @brief Print TCPV4 header.
 * 
 * @param packet 
 * @param verbose 
 * @param tcp_header 
 * @param options_length
 * @param version
 */
int print_tcpv4(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header,uint16_t *options_length,int version);


/**
 * @brief Print TCPV6 header.
 * 
 * @param packet 
 * @param verbose 
 * @param tcp_header 
 * @param options_length
 */
int print_tcpv6(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header,uint16_t *options_length);




/**
 * @brief Display TCP header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 * @param options_length
 */
int tcp(const unsigned char* packet, int verbose, int type,uint16_t *options_length);