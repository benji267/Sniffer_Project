#include "ethernet.h"
#include "ip.h"
#include <netinet/sctp.h>

#define CHUNK_TYPE_DATA 0
#define CHUNK_TYPE_INIT 1
#define CHUNK_TYPE_INIT_ACK 2
#define CHUNK_TYPE_SACK 3
#define CHUNK_TYPE_HEARTBEAT 4
#define CHUNK_TYPE_HEARTBEAT_ACK 5
#define CHUNK_TYPE_ABORT 6
#define CHUNK_TYPE_SHUTDOWN 7
#define CHUNK_TYPE_SHUTDOWN_ACK 8
#define CHUNK_TYPE_ERROR 9
#define CHUNK_TYPE_COOKIE_ECHO 10
#define CHUNK_TYPE_COOKIE_ACK 11
#define CHUNK_TYPE_ECNE 12
#define CHUNK_TYPE_CWR 13
#define CHUNK_TYPE_SHUTDOWN_COMPLETE 14


struct sctp{
    uint16_t source;
    uint16_t dest;
    uint32_t verification_tag;
    uint32_t checksum;
};

struct sctp_chunk{
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

/**
 * @brief   Prints the SCTP chunk.
 * 
 * @param   packet
 * @param   offset
 */
void print_chunkv4(const unsigned char *packet, uint8_t offset);



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