#include "tcp.h"	
#include "udp.h"

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