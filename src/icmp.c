#include "icmp.h"



void print_icmpv4_type(int type){
    switch(type){
        case ICMP_ECHOREPLY:
            printf("(Echo (ping) Reply)\n");
            break;
        case ICMP_ECHO:
            printf("(Echo (ping) Request)\n");
            break;
        case ICMP_DEST_UNREACH:
            printf("(Destination Unreachable)\n");
            break;
        default:
            printf("(Other)\n");
            break;
    }
}

void print_icmpv6_type(int type){
    switch(type){
        case ICMP6_ECHO_REQUEST:
            printf("Type: Echo (ping) Request ");
            break;
        case ICMP6_ECHO_REPLY:
            printf("Type: Echo (ping) Reply ");
            break;
        case ICMP6_DST_UNREACH:
            printf("Type: Destination Unreachable ");
            break;
        default:
            printf("Type: Other ");
            break;
    }
}


void print_icmpv4(const unsigned char* packet,struct icmphdr *icmp_header, int verbose){
    uint8_t icmp_type = ntohs(icmp_header->type);
    printf("Type: %x ", icmp_type);
    print_icmpv4_type(icmp_type);
    printf("\n");

    if(verbose>1){
        printf("Code: %x\n", icmp_header->code);
        printf("Checksum: %x\n", ntohs(icmp_header->checksum));
        printf("\n");
    }
    if(verbose>2){
        if(icmp_type == ICMP_ECHO || icmp_type == ICMP_ECHOREPLY){
            printf("Identifier: %x\n", ntohs(icmp_header->un.echo.id));
            printf("Sequence Number: %x\n", ntohs(icmp_header->un.echo.sequence));
        }
        else if(icmp_type == ICMP_DEST_UNREACH){
            printf("Unused: %x\n", ntohs(icmp_header->un.gateway));
        }
        printf("Reste du paquet ICMP: \n");
        for(int i=0; i<8; i++){
            printf("%x ", packet[14+sizeof(struct iphdr)+i]);
        }
        printf("\n");
    }
    return ;
}


void print_icmpv6(const unsigned char* packet,struct icmp6_hdr *icmp6_header, int verbose){
    uint8_t icmp_type = icmp6_header->icmp6_type & 0xFF;
    print_icmpv6_type(icmp_type);
    printf("(%u)\n ", icmp_type);
    printf("\n");

    if(verbose>1){
        printf("Code: %u\n", icmp6_header->icmp6_code);
        printf("Checksum: %x\n", ntohs(icmp6_header->icmp6_cksum));
        printf("\n");
    }
    if(verbose>2){
        if(icmp_type == ICMP6_ECHO_REQUEST || icmp_type == ICMP6_ECHO_REPLY){
            printf("Identifier: %x\n", ntohs(icmp6_header->icmp6_id));
            printf("Sequence Number: %u\n", ntohs(icmp6_header->icmp6_seq));
        }
        
        printf("Reste du paquet ICMP: \n");
        for(int i=0; i<8; i++){
            printf("%x ", packet[14+sizeof(struct ip6_hdr)+i]);
        }
        printf("\n");
    }
    return ;
}


void icmp(const unsigned char* packet, int verbose, int type){
    switch(type){
        case 4:
            printf("Protocol ICMPV4: \n");
            struct icmphdr *icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            print_icmpv4(packet, icmp_header, verbose);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        case 6:
            printf("Protocol ICMPV6: \n");
            struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            print_icmpv6(packet, icmp6_header, verbose);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        default:
            printf("Unknown\n");
            break;
    }
    return ;
}
