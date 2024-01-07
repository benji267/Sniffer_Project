#ifndef POP3_H
#define POP3_H

#include "tcp.h"
#include <ctype.h>


/**
 * @brief     Parse the pop3 packet
 *
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * @param option_length  The length of the option field
 * 
 */
void pop3(const unsigned char* packet, int verbose, int type, uint16_t *option_length);

#endif