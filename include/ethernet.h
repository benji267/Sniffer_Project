#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#define ETHERTYPE_IPV4_Custom 0x0800
#define ETHERTYPE_IPV6_Custom 0x86DD
#define ETHERTYPE_ARP_Custom 0x0806



/**
 * @brief fonction qui permet d'afficher le type de protocole ethernet.
 * 
 * @param type
 */

void print_type_ethernet(int type);


/**
 * @brief fonction permet d'afficher les informations de la trame ethernet selon la valeur de verbose.
 * 
 * @param packet
 * @param verbose
 */

int ethernet(const unsigned char *packet, int verbose);