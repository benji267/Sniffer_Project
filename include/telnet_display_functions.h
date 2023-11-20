#include "telnet.h"


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
 * @param end
 * 
 */
void print_telnet_option(const unsigned char *packet,int verbose,bool end);