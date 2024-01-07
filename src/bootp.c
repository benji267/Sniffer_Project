#include "bootp.h"


// Print the bootp message type.
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

// Print the bootp hardware type.
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

// Print the bootp message type depending on the verbose level to have the same display as wireshark.
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


// Print the bootp options depending on the verbose level to have the same display as wireshark.
//I check each option and print the information I can get from it.
//Some case need to print hexadecimal values, so I use the %02x format.
//For others, I just print the ascii value with %c.
//I need the verbose for the right display of the information.
//I use the packet pointer to get the information from the packet.
//BOOTP options looks like TLV (Type, Length, Value).
//So when I get the length, I add 1 to the pointer to get the value.
void print_bootp_option(int type,int verbose, const unsigned char* packet){
    switch(type){
        case 1:
            printf("(1) Subnet Mask (");
            packet+=2;
            printf("%d.%d.%d.%d)\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            if(verbose==3){
                printf("     |- Length: 4\n");
                printf("     |- Subnet Mask: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            }
            break;
        case 2:
            printf("(2) Time Offset\n");
            break;
        case 3:
            printf("(3) Router\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Router: ");
                printf("%d.%d.%d.%d", *packet, *(packet+1), *(packet+2), *(packet+3));
                printf("\n");
            }
            break;
        case 6:
            printf("(6) Domain Name Server\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                for(int i=0; i<length;i+=4){
                    printf("     |- Domain Name Server: ");
                    printf("%d.%d.%d.%d", *packet, *(packet+1), *(packet+2), *(packet+3));
                    printf("\n");
                    packet+=4;
                }
            }
            break;
        case 12:
            printf("(12) Host Name\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Host Name: ");
                for(int i=0; i<length; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 15:
            printf("(15) Domain Name\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Domain Name: ");
                for(int i=0; i<length; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 26:
            printf("(26) Interface MTU\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                packet++;
                printf("     |- Interface MTU: %d\n", *packet);
            }
            break;
        case 28:
            printf("(28) Broadcast Address\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                packet++;
                printf("     |- Broadcast Address: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            }
            break;
        case 33:
            printf("(33) Static Route\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                packet++;
                printf("     |- Static Route: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            }
            break;
        case 42:
            printf("(42) Network Time Protocol Servers\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                for(int i=0; i<length;i+=4){
                    printf("     |- Network Time Protocol Servers: ");
                    printf("%d.%d.%d.%d", *packet, *(packet+1), *(packet+2), *(packet+3));
                    printf("\n");
                    packet+=4;
                }
            }
            break;
        case 43:
            printf("(43) Vendor-Specific Information\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                packet++;
                printf("     |- Vendor-Specific Information: ");
                for(int i=0; i<length; i++){
                    printf("%02x", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 44:
            printf("(44) NetBIOS over TCP/IP Name Server\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                for(int i=0; i<length;i+=4){
                    printf("     |- NetBIOS over TCP/IP Name Server: ");
                    printf("%d.%d.%d.%d", *packet, *(packet+1), *(packet+2), *(packet+3));
                    printf("\n");
                    packet+=4;
                }
            }
            break;
        case 45:
            printf("(45) NetBIOS over TCP/IP Datagram Distribution Server\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                for(int i=0; i<length;i+=4){
                    printf("     |- NetBIOS over TCP/IP Datagram Distribution Server: ");
                    printf("%d.%d.%d.%d", *packet, *(packet+1), *(packet+2), *(packet+3));
                    printf("\n");
                    packet+=4;
                }
            }
            break;
        case 46:
            printf("(46) NetBIOS over TCP/IP Node Type\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                printf("     |- NetBIOS over TCP/IP Node Type: ");
                if(*packet==0x01){
                    printf("B-node (1)\n");
                }
                else if(*packet==0x02){
                    printf("P-node (2)\n");
                }
                else if(*packet==0x04){
                    printf("M-node (4)\n");
                }
                else if(*packet==0x08){
                    printf("H-node (8)\n");
                }
                else{
                    printf("Unknown\n");
                }
            }
            break;
        case 47:
            printf("(47) NetBIOS over TCP/IP Scope\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                printf("     |- NetBIOS over TCP/IP Scope: ");
                for(int i=0; i<length; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 50:
            printf("(50) Requested IP Address (");
            packet+=2;
            printf("%d.%d.%d.%d)\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            break;
        case 51:
            printf("(51) IP Address Lease Time\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                uint32_t seconds=0;
                seconds = (packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4];
                uint8_t hours=seconds/3600;
                printf("     |- IP Address Lease Time: %d hours (%d)\n", hours, seconds);
            }
            break;
        case 52:
            printf("(52) Option Overload\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                printf("     |- Option Overload: ");
                if(*packet==0x01){
                    printf("File and/or sname fields (1)\n");
                }
                else if(*packet==0x02){
                    printf("File only (2)\n");
                }
                else if(*packet==0x03){
                    printf("Boot file and sname fields (3)\n");
                }
                else{
                    printf("Unknown\n");
                }
            }
            break;
        case 53:
            printf("(53) DHCP Message Type (");
            print_bootp_message_type(*(packet+2),1);
            printf(")\n");
            if(verbose==3){
                printf("     |- Length: 1\n");
                printf("     |- DHCP: ");
                print_bootp_message_type(*(packet+2),3);
                printf("\n");
            }
            break;
        case 54:
            printf("(54) Server Identifier (");
            packet+=2;
            printf("%d.%d.%d.%d)\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            if(verbose==3){
                printf("     |- Length: 4\n");
                printf("     |- Server Identifier: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            }
            break;
        case 55:
            printf("(55) Parameter Request List\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                for(int i=0; i<length; i++){
                    printf("     |- Parameter Request List Item: ");
                    print_bootp_option(*packet,2,packet);
                    packet++;
                }
            }
            break;
        case 57:
            printf("(57) Maximum DHCP Message Size\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                uint16_t size=0;
                for(int i=0; i<2; i++){
                    size = (size << 8) | *packet;
                    packet++;
                }
                printf("     |- Maximum DHCP Message Size: %d bytes (%d)\n", size, size);
            }
            break;
        case 58:
            printf("(58) Renewal Time Value\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                uint32_t seconds=0;
                for(int i=0; i<4; i++){
                    seconds = (seconds << 8) | *packet;
                    packet++;
                }
                printf("     |- Renewal Time Value: %d seconds (%d)\n", seconds, seconds);
            }
            break;
        case 59:
            printf("(59) Rebinding Time Value\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                uint32_t seconds=0;
                for(int i=0; i<4; i++){
                    seconds = (seconds << 8) | *packet;
                    packet++;
                }
                printf("     |- Rebinding Time Value: %d seconds (%d)\n", seconds, seconds);
            }
            break;
        case 60:
            printf("(60) Vendor class identifier\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Vendor class identifier: ");
                for(int i=0; i<length; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 61:
            printf("(61) Client identifier\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Hardware type: %d\n", *packet);
                packet++;
                printf("     |- Client MAC adress: ");
                for(int i=0; i<length-1; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 66:
            printf("(66) TFTP Server Name\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- TFTP Server Name: ");
                for(int i=0; i<length; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 82:
            printf("(82) Agent Information Option\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Option: (82) Suboption: ");
                if(*packet==0x01){
                    printf("(1) Agent Circuit ID\n");
                    packet++;
                    uint16_t sub_length=*packet;
                    printf("         |- Length: %d\n", sub_length);
                    packet++;
                    printf("         |- Agent Circuit ID: ");
                    for(int i=0; i<sub_length; i++){
                        printf("%02x", *packet);
                        packet++;
                    }
                }
                else if(*packet==0x02){
                    printf("(2) Agent Remote ID\n");
                    packet++;
                    uint16_t sub_length=*packet;
                    printf("         |- Length: %d\n", sub_length);
                    packet++;
                    printf("         |- Agent Remote ID: ");
                    for(int i=0; i<sub_length; i++){
                        printf("%02x", *packet);
                        packet++;
                    }
                }
                else{
                    printf("Unknown\n");
                }
                printf("\n");
            }
            break;
        case 90:
            printf("(90) Authentication\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Protocol: ");
                if(*packet==0x01){
                    printf("delayed authentication (1)\n");
                    packet++;
                    printf("     |- Delay Algorithm: ");
                    char* algorithm;
                    if(*packet==0x01){
                        algorithm="HMAC MD5";
                        printf("HMAC-MD5 (1)\n");
                    }
                    else if(*packet==0x02){
                        algorithm="RSA MD5";
                        printf("RSA-MD5 (2)\n");
                    }
                    else if(*packet==0x03){
                        algorithm="RSA SHA-1";
                        printf("RSA-SHA-1 (3)\n");
                    }
                    else if(*packet==0x04){
                        algorithm="RSA SHA-256";
                        printf("RSA-SHA-256 (4)\n");
                    }
                    else if(*packet==0x05){
                        algorithm="RSA SHA-512";
                        printf("RSA-SHA-512 (5)\n");
                    }
                    else{
                        printf("Unknown\n");
                    }
                    packet++;
                    printf("     |- Replay Detection Method: ");
                    if(*packet==0x00){
                        printf("Monotonically-increasing counter (0)\n");
                    }
                    else if(*packet==0x01){
                        printf("Timestamp (1)\n");
                    }
                    else{
                        printf("Unknown\n");
                    }
                    packet++;
                    printf("     |- RDM Replay Detection Value: 0x");
                        for(int i=0; i<8; i++){
                            printf("%02x", *packet);
                            packet++;
                        }
                    printf("\n");
                    printf("     |- Secret ID: 0x");
                    for(int i=0; i<4; i++){
                        printf("%02x", *packet);
                        packet++;
                    }
                    printf("\n");
                    printf("     |- %s Hash: ", algorithm);
                    for(int i=0; i<16; i++){
                        printf("%02x", *packet);
                        packet++;
                    }
                    printf("\n");
                }
                else if(*packet==0x02){
                    printf("reconfig authentication (2)\n");
                    packet++;
                    printf("     |- Reconfig Message Type: ");
                    if(*packet==0x01){
                        printf("Information Request (1)\n");
                    }
                    else if(*packet==0x02){
                        printf("Information Reply (2)\n");
                    }
                    else if(*packet==0x03){
                        printf("Request (3)\n");
                    }
                    else if(*packet==0x04){
                        printf("Reply (4)\n");
                    }
                    else if(*packet==0x05){
                        printf("Commit (5)\n");
                    }
                    else{
                        printf("Unknown\n");
                    }
                    packet++;
                    printf("     |- Reconfig Message ID: ");
                    for(int i=0; i<4; i++){
                        printf("%02x", *packet);
                        packet++;
                    }
                    printf("\n");
                   //Don't know how to print the rest

                }
                else{
                    printf("Unknown\n");
                }
            }
            break;
        case 119:
            printf("(119) Domain Search\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                packet++;
                printf("     |- Domain Search: ");
                for(int i=0; i<length; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 120:
            printf("(120) SIP Servers\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- SIP Server Encoding: ");
                if(*packet==0x01){
                    printf("IPv4 Adress (1)\n");
                    packet++;
                }
                else if(*packet==0x02){
                    printf("IPv6 Adress (2)\n");
                    packet++;
                }
                else if(*packet==0x03){
                    printf("Fully Qualified Domain Name (3)\n");
                    packet++;
                }
                else{
                    printf("Unknown\n");
                    packet++;
                }
                printf("     |- SIP Server: %d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
            }
            break;
        case 121:
            printf("(121) Classless Static Route\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                packet++;
                printf("     |- Subnet Mask: ");
                for(int i=0; i<length; i++){
                    printf("%02x", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 150:
            printf("(150) TFTP Server Address\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                printf("     |- Length: %d\n", length);
                packet++;
               for(int i=0; i<length;i+=4){
                    printf("     |- TFTP Server Address: ");
                    printf("%d.%d.%d.%d", *packet, *(packet+1), *(packet+2), *(packet+3));
                    printf("\n");
                    packet+=4;
                }
            }
            break;
        case 249:
            printf("(249) Private/Classless Static Route (Microsoft)\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- Subnet Mask: ");
                for(int i=0; i<length; i++){
                    printf("%02x", *packet);
                    packet++;
                }
                printf("\n");
            }
            break;
        case 252:
            printf("(252) Private Proxy Auto-Discovery (Microsoft)\n");
            if(verbose==3){
                packet++;
                uint16_t length=*packet;
                packet++;
                printf("     |- Length: %d\n", length);
                printf("     |- PAC File: ");
                for(int i=0; i<length; i++){
                    printf("%c", *packet);
                    packet++;
                }
                printf("\n");
            }
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
    //Create a pointer to the beginning of the DHCP packet named after_magic_cookie to simplify the understanding of the code.
    const unsigned char* after_magic_cookie = packet;
    while(*after_magic_cookie!=0x63 && *after_magic_cookie!=0x82 && *after_magic_cookie!=0x53 && *after_magic_cookie!=0x63){
        after_magic_cookie++;
    }
    after_magic_cookie+=6;
    print_bootp_message_type(*after_magic_cookie,1);
    printf(")\n");
    //Print the verbose 1 as Wireshark does.
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
        //Ternary operator to print the right value of the flags.
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
        //If the packet==0x00, it means that the server host name is not given.
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
        //If the packet==0x00, it means that the boot file name is not given.
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
        //I found the magic cookie by looking for the 0x63, 0x82, 0x53, 0x63 values.
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
        //Loop to print all the options.
        while(*packet!=0xff){
            printf(" |- Option: ");
            print_bootp_option(*packet,verbose,packet);
            packet++;
            uint8_t length = *packet;
            length++;
            packet+=length;
        }
        packet++;
        printf(" |- Option: (255) End\n");
        if(verbose==3){
            printf("     |- Option End: 255\n");
        } 
    }
    return;
}