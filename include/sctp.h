#include "ethernet.h"
#include "ip.h"
#include <netinet/sctp.h>


struct sctp{
    uint16_t source;
    uint16_t dest;
    uint32_t verification_tag;
    uint32_t checksum;
};



/**
 * @brief  Prints the SCTPV4 header.
 * 
 * @param   packet
 * @param   sctp_header
 * @param   verbosity
 */
void print_sctpv4(const unsigned char* packet, int verbosity, const struct sctp* sctp_header);



/**
 * @brief   Prints the SCTP header.
 * 
 * @param   packet      
 * @param   verbosity
 * @param   type
 */
void sctp(const unsigned char* packet, int verbosity, int type);