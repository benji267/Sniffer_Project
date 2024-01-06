#include "tcp.h"
#include "ip.h"
#include "ethernet.h"


/**
 * @brief Display FTP packet
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 * @param option_length 
 */
void ftp(const unsigned char* packet, int verbose, int type, uint16_t *option_length);