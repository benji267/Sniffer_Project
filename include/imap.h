#include "tcp.h"
#include "ip.h"
#include "ethernet.h"
#include <ctype.h>

/**
 * @brief  IMAP protocol analysis
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 * @param option_length 
 */
void imap(const unsigned char* packet, int verbose, int type, uint16_t *option_length);