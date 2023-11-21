#include "telnet.h"




/**
 * @brief Print Telnet option at verbose level 2.
 * 
 * @param packet 
 * @param end boolean to know if the command is the last one and to stop the recursion
 * @param suboption boolean to know if the command is a suboption to wait for the end of the suboption marker
 * 
 */
void print_telnet_option(const unsigned char **packet,bool s_end,bool suboption);



/**
 * @brief Print Telnet command at verbose level 2.
 * 
 * @param packet
 * 
 */
void print_telnet_commandv2(const unsigned char **packet);



/**
 * @brief Print Telnet command at verbose level 3.
 * 
 * @param packet
 * 
 */
void print_telnet_commandv3(const unsigned char **packet);