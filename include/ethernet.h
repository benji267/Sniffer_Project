#ifndef ETHERNET_H
#define ETHERNET_H

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#define ETHERTYPE_IPV4_Custom 0x0800
#define ETHERTYPE_IPV6_Custom 0x86DD
#define ETHERTYPE_ARP_Custom 0x0806



/**
 * @brief function that prints the type of material.
 * 
 * @param type
 */

void print_type_ethernet(int type);


/**
 * @brief function that prints the ethernet packet with the verbose level and the same display as wireshark.
 * 
 * @param packet
 * @param verbose
 */

int ethernet(const unsigned char *packet, int verbose);

#endif