#include "icmp.h"


// Display the ICMPV4 protocol type.
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
        case ICMP_SOURCE_QUENCH:
            printf("(Source Quench)\n");
            break;
        case ICMP_REDIRECT:
            printf("(Redirect (change route))\n");
            break;
        default:
            printf("(Other)\n");
            break;
    }
}

// Display the ICMPV6 protocol type with more type than ICMPV4 because ICMPV6 has more type.
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
        case ICMP6_PACKET_TOO_BIG:
            printf("Type: Packet Too Big ");
            break;
        case ICMP6_TIME_EXCEEDED:
            printf("Type: Time Exceeded ");
            break;
        case ICMP6_PARAM_PROB:
            printf("Type: Parameter Problem ");
            break;
        case 135:
            printf("Type: Neighbor Solicitation ");
            break;
        case 136:
            printf("Type: Neighbor Advertisement ");
            break;
        default:
            printf("Type: Other ");
            break;
    }
}


//For ICMPV4, there's less information to display than ICMPV6 so that's why there's no verbose>2.
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
    printf("v6, ");
    uint8_t icmp_type = icmp6_header->icmp6_type & 0xFF;
    printf("\n");

    if(verbose>1){
        printf(" |- Type: ");
        print_icmpv6_type(icmp_type);
        printf(" (%u)\n", icmp_type);
        printf(" |- Code: %u\n", icmp6_header->icmp6_code);
        printf(" |- Checksum: 0x%x\n", ntohs(icmp6_header->icmp6_cksum));
        //each type has different information to display.
        if(icmp_type == ICMP6_ECHO_REQUEST || icmp_type == ICMP6_ECHO_REPLY){
            printf(" |- Identifier: 0x%04x\n", ntohs(icmp6_header->icmp6_id));
            printf(" |- Sequence Number: %d\n", ntohs(icmp6_header->icmp6_seq));
        }
        if(icmp_type == ICMP6_PACKET_TOO_BIG){
            printf(" |- MTU: %d\n", icmp6_header->icmp6_mtu);
        }
        if(icmp_type == ICMP6_PARAM_PROB){
            printf(" |- Pointer: %d\n", icmp6_header->icmp6_pptr);
        }
        //For the Neighbor Solicitation and Neighbor Advertisement, there is more information to display.
        //That's why there is a verbose>2 and why these two types are more way bigger than the others.
        //To find the information, I search in the packet with the size of the ICMPV6 header and I display the information.
        if(icmp_type == 135){
            packet+=sizeof(struct ether_header) + sizeof(struct ip6_hdr);
            packet+=4;
            printf(" |- Reserved:%02x%02x%02x%02x\n", packet[0], packet[1], packet[2], packet[3]);
            packet+=4;
            printf(" |- Target Address:");
            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, packet, str, INET6_ADDRSTRLEN);
            printf("%s\n", str);
            printf(" |- ICMPv6 Option (");
            packet+=16;
            if(packet[0]==1){
                printf("Source Link-Layer Address: ");
                printf("%02x:%02x:%02x:%02x:%02x:%02x)", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                if(verbose>2){
                    printf("     |- Type: Source link-layer address (1)\n");
                    printf("     |- Length: %d ( %d bytes)\n", packet[1], packet[1]*8);
                    printf("     |- Link-Layer Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                }
            }
            else if(packet[0]==2){
                printf("Target Link-Layer Address: ");
                printf("%02x:%02x:%02x:%02x:%02x:%02x)", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                if(verbose>2){
                    printf("     |- Type: Target link-layer address (2)\n");
                    printf("     |- Length: %d ( %d bytes)\n", packet[1], packet[1]*8);
                    printf("     |- Link-Layer Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                }
            }
            else if(packet[0]==3){
                printf("Prefix Information");
                if(verbose>2){
                    printf("     |- Type: Prefix information (3)\n");
                    printf("     |- Length: %d\n", packet[1]);
                    printf("     |- Prefix Length: %d\n", packet[2]);
                    printf("     |- Flag: %02x%02x%02x%02x\n", packet[3], packet[4], packet[5], packet[6]);
                    printf("     |- Valid Lifetime: %d\n", packet[7]*256+packet[8]);
                    printf("     |- Preferred Lifetime: %d\n", packet[9]*256+packet[10]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[11], packet[12], packet[13], packet[14]);
                    printf("     |- Prefix: %02x%02x:%02x%02x:%02x%02x:%02x%02x\n", packet[15], packet[16], packet[17], packet[18], packet[19], packet[20], packet[21], packet[22]);
                }
            }
            else if(packet[0]==4){
                printf("Redirected Header");
                if(verbose>2){
                    printf("     |- Type: Redirected header (4)\n");
                    printf("     |- Length: %d\n", packet[1]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[2], packet[3], packet[4], packet[5]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[6], packet[7], packet[8], packet[9]);
                }
            }
            else if(packet[0]==5){
                printf("MTU");
                if(verbose>2){
                    printf("     |- Type: MTU (5)\n");
                    printf("     |- Length: %d\n", packet[1]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[2], packet[3], packet[4], packet[5]);
                    printf("     |- MTU: %02x%02x%02x%02x\n", packet[6], packet[7], packet[8], packet[9]);
                }
            }
            else{
                printf("Unknown");
            printf("\n");
            }
        }
        if(icmp_type == 136){
            packet+=sizeof(struct ether_header) + sizeof(struct ip6_hdr);
            packet+=4;
            printf(" |- Flags: 0x%02x%02x%02x%02x", packet[0], packet[1], packet[2], packet[3]);
            bool router=false;
            bool solicited=false;
            bool override=false;
            if(packet[0] & 0x80){
                printf(", Router");
                router=true;
            }
            if(packet[0] & 0x40){
                printf(", Solicited");
                solicited=true;
            }
            if(packet[0] & 0x20){
                printf(", Override");
                override=true;
            }
            printf("\n");
            if(verbose>2){  
                printf("     |- %s... .... .... .... = Router: %s\n", router?"1":"0", router?"Set":"Not set");
                printf("     |- .%s.. .... .... .... = Solicited: %s\n", solicited?"1":"0", solicited?"Set":"Not set");
                printf("     |- ..%s. .... .... .... = Override: %s\n", override?"1":"0", override?"Set":"Not set");
                printf("     |- ...0 0000 0000 0000 = Reserved: 0x%02x%02x\n", packet[1], packet[2]);

            }
            packet+=4;
            printf(" |- Target Address:");
            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, packet, str, INET6_ADDRSTRLEN);
            printf("%s\n", str);
            printf(" |- ICMPv6 Option (");
            packet+=16;
            if(packet[0]==1){
                printf("Source Link-Layer Address: ");
                printf("%02x:%02x:%02x:%02x:%02x:%02x)", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                if(verbose>2){
                    printf("     |- Type: Source link-layer address (1)\n");
                    printf("     |- Length: %d ( %d bytes)\n", packet[1], packet[1]*8);
                    printf("     |- Link-Layer Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                }
            }
            else if(packet[0]==2){
                printf("Target Link-Layer Address: ");
                printf("%02x:%02x:%02x:%02x:%02x:%02x)", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                if(verbose>2){
                    printf("     |- Type: Target link-layer address (2)\n");
                    printf("     |- Length: %d ( %d bytes)\n", packet[1], packet[1]*8);
                    printf("     |- Link-Layer Address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);
                }
            }
            else if(packet[0]==3){
                printf("Prefix Information");
                if(verbose>2){
                    printf("     |- Type: Prefix information (3)\n");
                    printf("     |- Length: %d\n", packet[1]);
                    printf("     |- Prefix Length: %d\n", packet[2]);
                    printf("     |- Flag: %02x%02x%02x%02x\n", packet[3], packet[4], packet[5], packet[6]);
                    printf("     |- Valid Lifetime: %d\n", packet[7]*256+packet[8]);
                    printf("     |- Preferred Lifetime: %d\n", packet[9]*256+packet[10]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[11], packet[12], packet[13], packet[14]);
                    printf("     |- Prefix: %02x%02x:%02x%02x:%02x%02x:%02x%02x\n", packet[15], packet[16], packet[17], packet[18], packet[19], packet[20], packet[21], packet[22]);
                }
            }
            else if(packet[0]==4){
                printf("Redirected Header");
                if(verbose>2){
                    printf("     |- Type: Redirected header (4)\n");
                    printf("     |- Length: %d\n", packet[1]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[2], packet[3], packet[4], packet[5]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[6], packet[7], packet[8], packet[9]);
                }
            }
            else if(packet[0]==5){
                printf("MTU");
                if(verbose>2){
                    printf("     |- Type: MTU (5)\n");
                    printf("     |- Length: %d\n", packet[1]);
                    printf("     |- Reserved: %02x%02x%02x%02x\n", packet[2], packet[3], packet[4], packet[5]);
                    printf("     |- MTU: %02x%02x%02x%02x\n", packet[6], packet[7], packet[8], packet[9]);
                }
            }
            else{
                printf("Unknown");
            printf("\n");
            }
        }
    }
        printf("\n");
    return ;
}


//Principal function which gonna call the other functions to display the information of the ICMP layer.
//It takes the packet and parse for the good length to have the beginning of the ICMP layer.
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
