#include "tcp.h"

#define NOP 241
#define DM 242
#define IP 244
#define AO 245
#define AYT 246
#define EC 247
#define EL 248
#define GA 249
#define SB 250
#define WILL 251
#define WONT 252
#define DO 253
#define DONT 254
#define IAC 255


/**
 * @brief Print Telnet command.
 * 
 * @param packet
 * @param verbose
 * 
 */
void print_telnet_command(const unsigned char *packet,int verbose);


/**
 * @brief Print Telnet option.
 * 
 * @param packet 
 * @param verbose 
 */
void print_telnet_option(const unsigned char *packet,int verbose);


/**
 * @brief  Telnet header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 * @param options_length
 */
void telnet(const unsigned char* packet, int verbose, int type,uint16_t *options_length);