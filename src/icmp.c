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
    printf("Src: %s, ", inet_ntoa(*(struct in_addr*)&packet[14+12]));
    printf("Dst: %s\n", inet_ntoa(*(struct in_addr*)&packet[14+16]));
    uint8_t icmp_type = ntohs(icmp_header->type);
    printf("\n");

    if(verbose>1){
        printf(" |- Type: %u ", icmp_type);
        print_icmpv4_type(icmp_type);
        printf(" |- Code: %u\n", icmp_header->code);
        printf(" |- Checksum: 0x%x\n", ntohs(icmp_header->checksum));
        printf(" |- Identifier (BE): %d (0x%04x)\n", ntohs(icmp_header->un.echo.id), ntohs(icmp_header->un.echo.id));
        printf(" |- Identifier (LE): %d (0x%04x)\n", icmp_header->un.echo.id, icmp_header->un.echo.id);
        printf(" |- Sequence Number (BE): %d (0x%04x)\n", ntohs(icmp_header->un.echo.sequence), ntohs(icmp_header->un.echo.sequence));
        printf(" |- Sequence Number (LE): %d (0x%04x)\n", icmp_header->un.echo.sequence, icmp_header->un.echo.sequence);
    }
    //There is no verbose>2 because there is no more information to display
    return ;
}


void print_icmpv6(const unsigned char* packet,struct icmp6_hdr *icmp6_header, int verbose){
    uint8_t icmp_type = icmp6_header->icmp6_type & 0xFF;
    print_icmpv6_type(icmp_type);
    printf("(%u)\n ", icmp_type);
    printf("\n");

    if(verbose>1){
        printf("Code: %u\n", icmp6_header->icmp6_code);
        printf("Checksum: 0x%x\n", ntohs(icmp6_header->icmp6_cksum));
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
    printf("Internet Control Message Protocol, ");
    switch(type){
        case 4:
            struct icmphdr *icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            print_icmpv4(packet, icmp_header, verbose);
            break;
        case 6:
            struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            print_icmpv6(packet, icmp6_header, verbose);
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("\n");
    return ;
}
