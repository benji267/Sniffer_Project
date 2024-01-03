#include "udp.h"
#include "ip.h"
#include "ethernet.h"


/**
 * @brief Print the bootp message type.
 * 
 * @param type 
 */
void print_bootp_message(int type);

/**
 * @brief Print the bootp hardware type.
 * 
 * @param type 
 */
void print_bootp_hardware(int type);

/**
 * @brief Print the bootp message type.
 * 
 * @param type 
 * @param verbose 
 */
void print_bootp_message_type(int type, int verbose);

/**
 * @brief Display the bootp header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 */
void bootp(const unsigned char* packet, int verbose, int type);