#include "tcp.h"	
#include "udp.h"
#include <ctype.h>



/**
 * @brief    print the class of the DNS packet for verbose mode 3
 * 
 * @param class The class to print
 */
void print_classv3(uint16_t class);

/**
 * @brief     print the type of the DNS packet for verbose mode 3
 * 
 * @param packet The packet to print
 * @param type The type to print
 * 
 */
void print_typev3(const unsigned char *packet,uint16_t type);




/**
 * @brief     print the class of the DNS packet for verbose mode 2
 * 
 * @param class The class to print
 */
void print_classv2(uint16_t class);

/**
 * @brief     print the type of the DNS packet for verbose mode 2
 * 
 * @param type The type to print
 * 
 */
void print_typev2(uint16_t type);



/**
 * @brief     print the DNS Answer 
 * 
 * @param packet The packet to print
 * @param verbose The verbose mode
 */
void dns_print_answers(const unsigned char *packet, int verbose);


/**
 * @brief     Print the DNS queries
 *
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * 
 */
void dns_print_queries(const unsigned char *packet, int verbose);


/**
 * @brief     Print the DNS packet
 *
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * @param MSB  The Most Significant Bit of QR
 * 
 */
void dns_print(const unsigned char *packet, int verbose,int MSB);

/**
 * @brief     get the Most Significant Bit of QR
 * 
 * @param byte The byte to parse
 * 
 */
int getQR(const unsigned char byte);

/**
 * @brief     Parse the DNS packet
 *
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * @param option_length  The length of the option field
 * @param protocol  The protocol before DNS (0: TCP, 1: UDP)
 * 
 */
void dns(const unsigned char *packet, int verbose,int type, uint16_t* option_length,int protocol);