#include "tcp.h"
#include "ip.h"
#include "ethernet.h"
#include "ctype.h"
#include <stdbool.h>



/**
 * @brief    Display the smtp packet
 * 
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * 
 */
void print_smtp(const unsigned char* packet, int verbose);


/**
 * @brief     Parse the smtp packet
 * 
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * @param option_length  The length of the option field
 * 
 */
void smtp(const unsigned char* packet, int verbose, int type, uint16_t *option_length);