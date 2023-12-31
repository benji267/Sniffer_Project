#include "ethernet.h"

// Print the type of the ethernet packet
void print_type_ethernet(int type){
    switch(type){
        case ETHERTYPE_IPV4_Custom:
            printf("IPV4 (0x0800)");
            break;
        case ETHERTYPE_IPV6_Custom:
            printf("IPV6 (0x86DD)");
            break;
        case ETHERTYPE_ARP_Custom:
            printf("ARP (0x0806)");
            break;
        default:
            printf("Unknown ");
            break;
    }
}

// Print the ethernet packet with the verbose level and the same display as wireshark
int ethernet(const unsigned char *packet, int verbose){
    struct ether_header *ethernet;
    ethernet = (struct ether_header *) packet;
    printf("Ethernet II, ");
    printf("Src: %02x:%02x:%02x:%02x:%02x:%02x -> ", 
        ethernet->ether_shost[0], ethernet->ether_shost[1], 
        ethernet->ether_shost[2], ethernet->ether_shost[3], 
        ethernet->ether_shost[4], ethernet->ether_shost[5]);
    printf(", Dst: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        ethernet->ether_dhost[0], ethernet->ether_dhost[1], 
        ethernet->ether_dhost[2], ethernet->ether_dhost[3], 
        ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

    if(verbose>1){
        printf(" |- Destination: %02x:%02x:%02x:%02x:%02x:%02x", 
            ethernet->ether_dhost[0], ethernet->ether_dhost[1], 
            ethernet->ether_dhost[2], ethernet->ether_dhost[3], 
            ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
        printf(" (%02x:%02x:%02x:%02x:%02x:%02x)\n", 
            ethernet->ether_dhost[0], ethernet->ether_dhost[1], 
            ethernet->ether_dhost[2], ethernet->ether_dhost[3], 
            ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
        if(verbose>2){
            printf( " |- Adress: %02x:%02x:%02x:%02x:%02x:%02x",
                ethernet->ether_dhost[0], ethernet->ether_dhost[1], 
                ethernet->ether_dhost[2], ethernet->ether_dhost[3], 
                ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
            printf(" (%02x:%02x:%02x:%02x:%02x:%02x)\n", 
                ethernet->ether_dhost[0], ethernet->ether_dhost[1], 
                ethernet->ether_dhost[2], ethernet->ether_dhost[3], 
                ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
            printf("     |- .... ..%s.  .... .... .... .... = LG bit:", 
                ethernet->ether_dhost[0]&0x02?"1":"0");
                if(ethernet->ether_dhost[0]&0x02)
                    printf(" Locally administered address (this is NOT the factory default)\n");
                else
                    printf(" Globally unique address (factory default)\n");
                
            printf("     |- .... ...%s  .... .... .... .... = IG bit: ",
                ethernet->ether_dhost[0]&0x01?"1":"0");//ternary operator to print 1 or 0
                if(ethernet->ether_dhost[0]&0x01)
                    printf("Group address (multicast/broadcast)\n");
                else
                    printf("Individual address (unicast)\n");
        }
        printf(" |- Source: %02x:%02x:%02x:%02x:%02x:%02x",
            ethernet->ether_shost[0], ethernet->ether_shost[1], 
            ethernet->ether_shost[2], ethernet->ether_shost[3], 
            ethernet->ether_shost[4], ethernet->ether_shost[5]);
        printf(" (%02x:%02x:%02x:%02x:%02x:%02x)\n",
            ethernet->ether_shost[0], ethernet->ether_shost[1], 
            ethernet->ether_shost[2], ethernet->ether_shost[3], 
            ethernet->ether_shost[4], ethernet->ether_shost[5]);
        if(verbose>2){
            printf(" |- Adress: %02x:%02x:%02x:%02x:%02x:%02x",
                ethernet->ether_shost[0], ethernet->ether_shost[1], 
                ethernet->ether_shost[2], ethernet->ether_shost[3], 
                ethernet->ether_shost[4], ethernet->ether_shost[5]);
            printf(" (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                ethernet->ether_shost[0], ethernet->ether_shost[1], 
                ethernet->ether_shost[2], ethernet->ether_shost[3], 
                ethernet->ether_shost[4], ethernet->ether_shost[5]);

            printf("     |- .... ..%s.  .... .... .... .... = LG bit:", 
                ethernet->ether_shost[0]&0x02?"1":"0"); //ternary operator to print 1 or 0
                if(ethernet->ether_shost[0]&0x02) 
                    printf(" Locally administered address (this is NOT the factory default)\n");
                else
                    printf(" Globally unique address (factory default)\n");
                
            printf("     |- .... ...%s  .... .... .... .... = IG bit: ",
                ethernet->ether_shost[0]&0x01?"1":"0");
                if(ethernet->ether_shost[0]&0x01)
                    printf("Group address (multicast/broadcast)\n");
                else
                    printf("Individual address (unicast)\n");
        }
        printf(" |- Type: ");
        print_type_ethernet(ntohs(ethernet->ether_type));
        printf("\n");
    }
    printf("\n");
    return ntohs(ethernet->ether_type); //return the type of the packet for the next step
}