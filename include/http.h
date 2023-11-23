#include "tcp.h"
#include <ctype.h>
#include <stdbool.h>




/**
 * @brief HTTP header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 * @param option_length 
 */
void http(const unsigned char* packet, int verbose, int type,uint16_t *option_length);