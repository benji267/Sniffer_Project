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

void print_bootp_option(int type,int verbose, const unsigned char* packet){
    switch(type){
        case 1:
            printf("(1) Subnet Mask (");
            packet+=2;
            printf("%d.%d.%d.%d)\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            break;
        case 2:
            printf("(2) Time Offset\n");
            break;
        case 3:
            printf("(3) Router\n");
            break;
        case 6:
            printf("(6) Domain Name Server\n");
            break;
        case 12:
            printf("(12) Host Name\n");
            break;
        case 15:
            printf("(15) Domain Name\n");
            break;
        case 26:
            printf("(26) Interface MTU\n");
            break;
        case 28:
            printf("(28) Broadcast Address\n");
            break;
        case 42:
            printf("(42) Network Time Protocol Servers\n");
            break;
        case 43:
            printf("(43) Vendor-Specific Information\n");
            break;
        case 44:
            printf("(44) NetBIOS over TCP/IP Name Server\n");
            break;
        case 45:
            printf("(45) NetBIOS over TCP/IP Datagram Distribution Server\n");
            break;
        case 46:
            printf("(46) NetBIOS over TCP/IP Node Type\n");
            break;
        case 47:
            printf("(47) NetBIOS over TCP/IP Scope\n");
            break;
        case 50:
            printf("(50) Requested IP Address (");
            packet+=2;
            printf("%d.%d.%d.%d)\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            break;
        case 51:
            printf("(51) IP Address Lease Time\n");
            break;
        case 52:
            printf("(52) Option Overload\n");
            break;
        case 53:
            printf("(53) DHCP Message Type (");
            print_bootp_message_type(*(packet+2),1);
            printf(")\n");
            break;
        case 54:
            printf("(54) Server Identifier (");
            packet+=2;
            printf("%d.%d.%d.%d)\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            break;
        case 55:
            printf("(55) Parameter Request List\n");
            break;
        case 57:
            printf("(57) Maximum DHCP Message Size\n");
            break;
        case 58:
            printf("(58) Renewal Time Value\n");
            break;
        case 59:
            printf("(59) Rebinding Time Value\n");
            break;
        case 60:
            printf("(60) Vendor class identifier\n");
            break;
        case 61:
            printf("(61) Client identifier\n");
            break;
        case 66:
            printf("(66) TFTP Server Name\n");
            break;
        case 82:
            printf("(82) Agent Information Option\n");
            break;
        case 90:
            printf("(90) Authentication\n");
            break;
        case 119:
            printf("(119) Domain Search\n");
            break;
        case 120:
            printf("(120) SIP Servers\n");
            break;
        case 121:
            printf("(121) Classless Static Route\n");
            break;
        case 249:
            printf("(249) Private/Classless Static Route (Microsoft)\n");
            break;
        case 252:
            printf("(252) Private Proxy Auto-Discovery (Microsoft)\n");
            break;
        default:
            printf("Unknown\n");
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
        printf(" |- Hardware type: ");
        print_bootp_hardware(*packet);
        printf("\n");
        packet++;
        printf(" |- Hardware address length: %d\n", *packet);
        packet++;
        printf(" |- Hops: %d\n", *packet);
        packet++;
        printf(" |- Transaction ID: 0x%02x%02x%02x%02x\n", *packet, *(packet+1), *(packet+2), *(packet+3));
        packet+=4;

        uint16_t seconds = (packet[0] << 8) | packet[1];
        printf(" |- Seconds elapsed: %d\n", seconds);
        packet+=2;
        printf(" |- Bootp flags: 0x%02x%02x", *packet, *(packet+1));
        if(*packet & 0x80){
            printf(" (Broadcast)");
        }
        else{
            printf(" (Unicast)");
        }
        if(*packet & 0x40){
            printf(" (Reserved)");
        }
        printf("\n");
        if(verbose==3){
            printf("     |- %s... ....= Broadcast flag: %s\n", (*packet & 0x80)? "1":"0", (*packet & 0x80)?"Broadcast":"Unicast");
            printf("     |- .%s.. ....= Reserved flags: 0x%04x\n", (*packet & 0x40)?"1":"0", (*packet & 0x40));
        }
        packet+=2;
        printf(" |- Client IP address: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
        packet+=4;
        printf(" |- Your (client) IP address: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
        packet+=4;
        printf(" |- Next server IP address: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
        packet+=4;
        printf(" |- Relay agent IP address: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
        packet+=4;
        printf(" |- Client MAC address: %02x:%02x:%02x:%02x:%02x:%02x (%02x:%02x:%02x:%02x:%02x:%02x)\n", 
        *packet, *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5),
        *packet, *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5));
        packet+=6;
        printf(" |- Client hardware address padding: ");
        for(int i=0; i<10; i++){
            printf("%02x", *packet);
            packet++;
        }
        printf("\n");
        printf(" |- Server host name: ");
        for(int i=0; i<64; i++){
            if(*packet==0x00){
                printf("not given");
                packet+=64-i;
                break;
            }
            printf("%c", *packet);
            packet++;
        }
        printf("\n");
        printf(" |- Boot file name: ");
        for(int i=0; i<128; i++){
            if(*packet==0x00){
                printf("not given");
                packet+=128-i;
                break;
            }
            printf("%c", *packet);
            packet++;
        }
        printf("\n");
        if(*packet== 0x63 && *(packet+1)==0x82 && *(packet+2)==0x53 && *(packet+3)==0x63){
            printf(" |- Magic cookie: DHCP\n");
            packet+=4;
        }
        else{
            printf(" |- Magic cookie: ");
            for(int i=0; i<4; i++){
                printf("%02x", *packet);
                packet++;
            }
            printf("\n");
        }
        while(*packet!=0xff){
            printf(" |- Option: ");
            print_bootp_option(*packet,verbose,packet);
            packet++;
            uint8_t length = *packet;
            length++;
            packet+=length;
        }
        printf(" |- Option: (255) End\n");
        if(verbose==3){
            printf("     |- Option End: 255\n");
        }    
    }
    return;
}