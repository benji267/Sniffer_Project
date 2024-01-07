#include "sctp.h"

//I was thinking that I have to code the SCTP protocol but I don't have to. I let this file here.

void print_chunkv4(const unsigned char *packet, uint8_t offset){}

void print_sctpv4(const unsigned char* packet, int verbosity, const struct sctp* sctp_header){
    printf("Source Port: %d -> ", ntohs(sctp_header->source));
    printf("Destination Port: %d\n", ntohs(sctp_header->dest));
    printf("\n");
    if(verbosity>1){
        printf("Verification Tag: 0x%x\n", ntohl(sctp_header->verification_tag));
        printf("Checksum: 0x%x\n", ntohl(sctp_header->checksum));
    }
    if(verbosity>2){
        print_chunkv4(packet, sizeof(struct sctp));     
    }

}

void sctp(const unsigned char* packet, int verbosity, int type){
    switch(type){
        case 4: 
            const struct sctp* sctp = (struct sctp*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("Prorocol SCTPV4:\n");
            print_sctpv4(packet,verbosity,sctp);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
    }
}