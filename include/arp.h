#ifndef ARP_H
#define ARP_H

#include "ethernet.h"
#include "ip.h"
#include <netinet/if_ether.h>
#include <net/if_arp.h>




/**
 * @brief Display the type of material.
 * 
 * @param type 
 */
void print_hardware_type(int type);

/**
 * @brief Display the ARP opcode.
 * 
 * @param opcode
 */
void print_arp_opcode(int opcode);


/**
 * @brief Display the ARP packet with the verbose level and the same display as wireshark.
 * 
 * @param packet 
 * @param verbose 
 */
int arp(const unsigned char *packet, int verbose);

#endif