#include "arp.h"



void print_harware_type(int type){
    switch(type){
        case ARPHRD_NETROM:
            printf("NET/ROM ");
            break;
        case ARPHRD_ETHER:
            printf("Ethernet ");
            break;
        default:
            printf("Unknown");
            break;
    }
    return ;
}

void print_arp_opcode(int opcode){
    switch(opcode){
        case ARPOP_REQUEST:
            printf("ARP Request");
            break;
        case ARPOP_REPLY:
            printf("ARP Reply");
            break;
        case ARPOP_RREQUEST:
            printf("RARP Request");
            break;
        case ARPOP_RREPLY:
            printf("RARP Reply");
            break;
        case ARPOP_InREQUEST:
            printf("InARP Request");
            break;
        case ARPOP_InREPLY:
            printf("InARP Reply");
            break;
        case ARPOP_NAK:
            printf("NAK");
            break;
        default:
            printf("Unknown opcode");
            break;
    }
    return ;
}




int arp(const unsigned char *packet,int verbose){
    printf("Protocol ARP: ");
    const struct arphdr *arp_header = (struct arphdr*)(packet+14);

    printf("Sender MAC -> Target MAC: ");
    for(int i=0;i<6;i++){
        printf("%02x", packet[22+i]);
        if(i<5){
            printf(":");
        }
    }
    printf(" -> ");
    for(int i=0;i<6;i++){
        printf("%02x", packet[32+i]);
        if(i<5){
            printf(":");
        }
    }

    printf(". Sender IP -> Target IP: ");
    for(int i=0;i<4;i++){
        printf("%d", packet[28+i]);
        if(i<3){
            printf(".");
        }
    }
    printf(" -> ");
    for(int i=0;i<4;i++){
        printf("%d", packet[38+i]);
        if(i<3){
            printf(".");
        }
    }
    printf("\n");
    

    if(verbose>1){
        printf("\n");
        printf("Opcode: ");
        print_arp_opcode(ntohs(arp_header->ar_op));
        printf("(%d)\n", ntohs(arp_header->ar_op));
        
        
    }
    
    if(verbose>2){
        printf("\n");
        printf("Hardware type: ");
        print_harware_type(ntohs(arp_header->ar_hrd));
        printf("(%d)\n", ntohs(arp_header->ar_hrd));
        printf("Protocol type: ");
        print_type_ethernet(ntohs(arp_header->ar_pro));
        printf("(0x%04X)\n", ntohs(arp_header->ar_pro));
        printf("Hardware size: %d\n", arp_header->ar_hln);
        printf("Protocol size: %d\n", arp_header->ar_pln);
        printf("\n");

    }
    


    for(int i=0;i<6;i++){
        printf("\n");
    }

    return 1;
}