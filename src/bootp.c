#include "bootp.h"

void print_bootp_message(int type){
    switch(type){
        case 1:
            printf("Boot Request (1)");
            break;
        case 2:
            printf("Boot Reply (2)");
            break;
        default:
            printf("Unknown");
            break;
    }
}


void print_bootp_hardware(int type){
    switch(type){
        case 1:
            printf("Ethernet (0x01)");
            break;
        case 6:
            printf("IEEE 802 Networks (0x06)");
            break;
        case 15:
            printf("Frame Relay (0x0F)");
            break;
        case 16:
            printf("Asynchronous Transfer Mode (ATM) (0x10)");
            break;
        default:
            printf("Unknown");
            break;
    }
}

void print_bootp_message_type(int type, int verbose){
    switch(type){
        case 1:
            printf("Discover");
            if(verbose>2)
                printf(" (1)");
            break;
        case 2:
            printf("Offer");
            if(verbose>2)
                printf(" (2)");
            break;
        case 3:
            printf("Request");
            if(verbose>2)
                printf(" (3)");
            break;
        case 5:
            printf("ACK");
            if(verbose>2)
                printf(" (5)");
            break;
    }
}

void print_bootp_option(int type,int verbose){
    switch(type){
        case 53:
            printf("DHCP Message Type");
            print_bootp_message_type(verbose,verbose);
            break;
    }
}


void bootp(const unsigned char* packet, int verbose, int type){
    printf("Dynamic Host Configuration Protocol (");
    switch(type){
        case 4:
            packet+=sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct udphdr);
            break;
        case 6:
            packet+=sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct udphdr);
            break;
    }
    const unsigned char* after_magic_cookie = packet;
    while(*after_magic_cookie!=0x63 && *after_magic_cookie!=0x82 && *after_magic_cookie!=0x53 && *after_magic_cookie!=0x63){
        after_magic_cookie++;
    }
    after_magic_cookie+=6;
    print_bootp_message_type(*after_magic_cookie,1);
    printf(")\n");
    if(verbose>1){
        printf(" |- Message type: ");
        print_bootp_message(*packet);
        printf("\n");
        packet++;
    }
}