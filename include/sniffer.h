#ifndef SNIFFER_H
#define SNIFFER_H

#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "sctp.h"
#include "telnet.h"
#include "http.h"
#include "pop3.h"
#include "dns.h"
#include "smtp.h"
#include "bootp.h"
#include "ftp.h"

//Useful to separate the different frames in the output terminal
void separe_trame(){
 printf("-------------------------------------------------------------------------------------------------------------------------------------\n");
}

//FakeFrame used to test the program without using the interface option or the pcap file option
unsigned char fakeFrame[] = {
        // Ethernet Header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Source MAC
        0x08, 0x00,                         // EtherType (IPv4)

        // IPv4 Header
        0x45, 0x00, 0x00, 0x3C,             // Version, Header Length, Type of Service, Total Length
        0x12, 0x34, 0x00, 0x00,             // Identification, Flags, Fragment Offset
        0x40, 0x06, 0xAB, 0xCD,             // Time to Live (TTL), Protocol (TCP), Header Checksum
        0xC0, 0xA8, 0x01, 0x64,             // Source IP (192.168.1.100)
        0xC0, 0xA8, 0x01, 0x01,             // Destination IP (192.168.1.1)

        // TCP Header
        0x30, 0x39, 0x00, 0x50,             // Source Port, Destination Port
        0xAA, 0xAA, 0xAA, 0xAA,             // Sequence Number
        0xBB, 0xBB, 0xBB, 0xBB,             // Acknowledgment Number
        0x50, 0x18, 0x20, 0x00,             // Data Offset, Flags (PSH, ACK), Window Size, Checksum
        0x00, 0x00, 0xEF, 0x01,             // Urgent Pointer

        // HTTP Data (GET Request)
       0x47, 0x45, 0x54, 0x20, 0x2F, 0x65, 0x78, 0x65, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x68, 0x74, 0x6D, 0x6C, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A,
       0x6E, 0x6F, 0x2D, 0x6F, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x65, 0x78, 0x65, 0x6D, 0x70, 0x6C, 0x65, 0x0D, 0x0A,
       0x0D, 0x0A

    };

    unsigned int nombre_de_trames = sizeof(fakeFrame);


/**
 * @brief    Parse the example packet
 * 
 * @param packet  The packet to parse
 * @param verbose  Verbose mode
 * 
 * 
 */
void example_packet(const unsigned char* packet, int verbose);

#endif