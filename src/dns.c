#include "dns.h"

int getQR(unsigned char byte){
    return byte >> 7;
}

void dns_print(const unsigned char *packet, int verbose,int MSB){
    printf("Transaction ID: 0x%02x%02x\n", packet[0], packet[1]);
    printf("Flags: 0x%02x%02x", packet[2], packet[3]);
    int flags=packet[2]*256 + packet[3];
    if(flags & 0x81){
        printf(" Standard query response, No error\n");
    }
    else{
        printf(" Standard query\n");
    }
                
    if(verbose>2){
        printf("%d... .... .... .... = Response: Message is a ", getQR(packet[2]));
        if(getQR(packet[2])==0){
            printf("query:\n");
        }
        else{
            printf("response:\n");
        }
        printf(".%d.. .... .... .... = Opcode: ", (packet[2] >> 3) & 0x1);
        switch((packet[2] >> 3) & 0x1){
            case 0:
                printf("standard query (0)\n");
                break;
            case 1:
                printf("inverse query (1)\n");
                break;
            case 2:
                printf("server status request (2)\n");
                break;
            case 3:
                printf("reserved (3)\n");
                break;
            case 4:
                printf("notify (4)\n");
                break;
            case 5:
                printf("update (5)\n");
                break;

            default:
                printf("Unknown\n");
                break;
        }
        if(MSB==1){
            printf("..%d. .... .... .... = Authoritative: ", (packet[2] >> 2) & 0x1);
            if((packet[2] >> 2) & (0x1==0)){
                printf("server is not an authority for domain\n");
                }
            else{
                printf("server is an authority for domain\n");
            }
        }
        printf("...%d .... .... .... = Truncated: ", (packet[2] >> 1) & 0x1);
        if((packet[2] >> 1) & (0x1==0)){
            printf("message is not truncated\n");
        }
        else{
            printf("message is truncated\n");
        }
        printf(".... %d... .... .... = Recursion desired: ", packet[2] & 0x1);
        if(packet[2] & (0x1==0)){
            printf("do not query recursively\n");
        }
        else{
            printf("do query recursively\n");
        }
        printf(".... .%d.. .... .... = Recursion available: ", packet[3] >> 7);
        if(packet[3] >> 7==0){
            printf("server can not query recursively\n");
        }
        else{
            printf("server can query recursively\n");
        }
        printf(".... ..%d. .... .... = Z: reserved (0)\n", (packet[3] >> 6) & 0x1);
        if(MSB==1){
            printf(".... ...%d .... .... = Answer authenticated: ", (packet[3] >> 5) & 0x1);
            if((packet[3] >> 5) & (0x1==0)){
                printf("answer/authority portion was not authenticated by the server\n");
            }
            else{
                printf("answer/authority portion was authenticated by the server\n");
            }
        }
        printf(".... .... %d... .... = Non-authenticated data: ", (packet[3] >> 4) & 0x1);
        if((packet[3] >> 4) & (0x1==0)){
            printf("unacceptable\n");
        }
        else{
            printf("acceptable\n");
        }
        if(MSB==1){
            printf(".... .... .%d.. .... = Reply code: ", packet[3] & 0xF); 
            switch(packet[3] & 0xF){
                case 0:
                    printf("No error (0)\n");
                    break;
                case 1:
                    printf("Format error (1)\n");
                    break;
                case 2:
                    printf("Server failure (2)\n");
                    break;
                case 3:
                    printf("Name Error (3)\n");
                    break;
                case 4:
                    printf("Not Implemented (4)\n");
                    break;
                case 5:
                    printf("Refused (5)\n");
                    break;
                case 6:
                    printf("YXDomain (6)\n");
                    break;
                case 7:
                    printf("YXRRSet (7)\n");
                    break;
                case 8:
                    printf("NXRRSet (8)\n");
                    break;
                case 9:
                    printf("NotAuth (9)\n");
                    break;
                case 10:
                    printf("NotZone (10)\n");
                    break;
                case 11:
                    printf("DSOTYPENI (11)\n");
                    break;
                case 12:
                    printf("Reserved (12)\n");
                    break;
                case 13:
                    printf("Reserved (13)\n");
                    break;
                case 14:
                    printf("Reserved (14)\n");
                    break;
                case 15:
                    printf("Reserved (15)\n");
                    break;
                default:
                    printf("Unknown\n");
                    break;
            }
        }
    }
    printf("Questions: %d\n", packet[4]*256 + packet[5]);
    printf("Answer RRs: %d\n", packet[6]*256 + packet[7]);
    printf("Authority RRs: %d\n", packet[8]*256 + packet[9]);
    printf("Additional RRs: %d\n", packet[10]*256 + packet[11]);
    

    printf("Queries");
    packet+=12;
    //I put packet in the first byte of the first query to simplify the code
    //Before I don't do that to avoid to modify the packet pointer and to underline the constant length of the header
    


    return ;
}

void dns(const unsigned char *packet, int verbose,int type, uint16_t* option_length,int protocol){
    printf("Domain Name System");
    const unsigned char * dns_packet;
    switch(type){
        case 4:
            switch(protocol){
                case 0:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + *option_length;
                    break;

                case 1:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
                    break;
                
                default:
                    printf("Unknown\n");
                    break;
            }
            
            int MSB=getQR(dns_packet[2]);
            if(MSB==1){
                printf(" (query)\n");
            }
            else{
                printf(" (response)\n");
            }

            if(verbose>1){
                dns_print(dns_packet, verbose, MSB);
            }

            break;
        case 6:
            switch(protocol){
                case 0:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + *option_length;
                    break;

                case 1:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
                    break;
                
                default:
                    printf("Unknown\n");
                    break;
            }
            MSB=getQR(dns_packet[2]);
            if(MSB==0){
                printf(" (query)\n");
            }
            else{
                printf(" (response)\n");
            }

            if(verbose>1){
                dns_print(dns_packet, verbose, MSB);
            }
            break;
        default:
            printf("Unknown\n");
            break;
    }
}