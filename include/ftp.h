#ifndef FTP_H
#define FTP_H

#include "tcp.h"
#include "ip.h"
#include "ethernet.h"
#include <ctype.h>

#define FTP_DATA 0
#define FTP_CMD_USER 1
#define FTP_CMD_PASS 2
#define FTP_CMD_CWD 3
#define FTP_CMD_PWD 4
#define FTP_CMD_PORT 5

/**
 * @brief Display FTP packet
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 * @param option_length 
 */
void ftp(const unsigned char* packet, int verbose, int type, uint16_t *option_length);

#endif