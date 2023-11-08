#include "ethernet.h"
#include "ip.h"
#include <netinet/if_ether.h>
#include <net/if_arp.h>





/**
 * @brief Affiche le type de protocole ARP.
 * 
 * @param opcode
 */
void print_arp_opcode(int opcode);


/**
 * @brief Affiche les informations de la couche ARP
 * 
 * @param packet 
 */
void print_verb_one(const unsigned char * packet);


/**
 * @brief Affiche les informations de la couche ARP.
 * 
 * @param packet 
 * @param verbose 
 */
int arp(const unsigned char *packet, int verbose);
