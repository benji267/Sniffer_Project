#include "tcp.h"	

/**
 * @brief     Parse the DNS packet
 *
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * @param option_length  The length of the option field
 * 
 */
void dns_parse(const unsigned char *packet, int verbose, ,int type, uint16_t* option_length);