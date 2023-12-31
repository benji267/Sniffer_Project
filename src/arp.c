#include "arp.h"

//These files don't have difficult functions, they just display the information.

void print_hardware_type(int type){
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
            printf("request");
            break;
        case ARPOP_REPLY:
            printf("reply");
            break;
        case ARPOP_RREQUEST:
            printf("rarp request");
            break;
        case ARPOP_RREPLY:
            printf("rarp reply");
            break;
        case ARPOP_InREQUEST:
            printf("InARP request");
            break;
        case ARPOP_InREPLY:
            printf("InARP reply");
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
    const struct arphdr *arp_header = (struct arphdr*)(packet+14);
    printf("Adress Resolution Protocol(");
    print_arp_opcode(ntohs(arp_header->ar_op));
    printf(")\n");

    if(verbose>1){
        printf(" |- Hardware type: ");
        print_hardware_type(ntohs(arp_header->ar_hrd));
        printf("(%d)\n", ntohs(arp_header->ar_hrd));
        printf(" |- Protocol type: ");
        print_type_ethernet(ntohs(arp_header->ar_pro));
        printf("\n");
        printf(" |- Hardware size: %d\n", arp_header->ar_hln);
        printf(" |- Protocol size: %d\n", arp_header->ar_pln);
        printf(" |- Opcode: ");
        print_arp_opcode(ntohs(arp_header->ar_op));
        printf(" (%d)\n", ntohs(arp_header->ar_op));
        printf(" |- Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x", 
            packet[22], packet[23], packet[24], packet[25], packet[26], packet[27]);
        printf(" (%02x:%02x:%02x:%02x:%02x:%02x)\n", 
            packet[22], packet[23], packet[24], packet[25], packet[26], packet[27]);
        printf(" |- Sender IP address: %d.%d.%d.%d\n",
            packet[28], packet[29], packet[30], packet[31]);
        printf(" |- Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
            packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
        printf(" (%02x:%02x:%02x:%02x:%02x:%02x)\n",
            packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
        printf(" |- Target IP address: %d.%d.%d.%d\n",
            packet[38], packet[39], packet[40], packet[41]);
    }   
    //There no verbose level 3 for arp because there is no more information to display
    //and zero playload.

    printf("\n");

    return 1;
}