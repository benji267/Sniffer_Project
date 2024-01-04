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
 * @brief Print the bootp options.
 * 
 * @param type 
 * @param verbose 
 * @param packet
 */
void print_bootp_options(int type, int verbose, const unsigned char* packet);

/**
 * @brief Display the bootp header.
 * 
 * @param packet 
 * @param verbose 
 * @param type 
 */
void bootp(const unsigned char* packet, int verbose, int type);