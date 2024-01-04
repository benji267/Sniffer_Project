#include "ip.h"



void print_protocol_ip(int protocol){
    switch(protocol){
        case IPPROTO_ICMP:
            printf("ICMPV4");
            break;
        case IPPROTO_ICMPV6:
            printf("ICMPV6");
            break;
        case IPPROTO_TCP:
            printf("TCP");
            break;
        case IPPROTO_UDP:
            printf("UDP");
            break;
        case IPPROTO_SCTP:
            printf("SCTP");
            break;
        default:
            printf("Unknown");
            break;
    }
    return ;
}

void print_flags(u_int16_t flags,int verbose){
    if(flags & IP_DF){
        printf("DF (Don't Fragment) \n");
        if(verbose>2){
            printf("     |- 0... .... = Reserved bit: Not set\n");
            printf("     |- .1.. .... = Don't fragment: Set\n");
            printf("     |- ..0. .... = More fragments: Not set\n");
        }
    }
    if(flags & IP_MF){
        printf("MF (More Fragments)\n ");
        if(verbose>2){
            printf("     |- 0... .... = Reserved bit: Not set\n");
            printf("     |- .0.. .... = Don't fragment: Not set\n");
            printf("     |- ..1. .... = More fragments: Set\n");
        }
    }
    if(flags & IP_RF){
        printf("RF (Reserved Flag)\n ");
        if(verbose>2){
            printf("     |- 1... .... = Reserved bit: Set\n");
            printf("     |- .0.. .... = Don't fragment: Not set\n");
            printf("     |- ..0. .... = More fragments: Not set\n");
        }
    }
    return ;
}


void print_ipv4(int verbose, struct iphdr *ip,u_int16_t flags){
    printf("4, ");
    printf("Src: %s, ", inet_ntoa(*(struct in_addr*)&ip->saddr));
    printf("Dst: %s", inet_ntoa(*(struct in_addr*)&ip->daddr));
    printf("\n");

    if(verbose>1){
        printf(" |- 0100 .... = Version: 4\n");
        printf(" |- .... 0101 = Header Length: 20 bytes (5)\n");
        printf(" |- Differentiated Services Field: 0x");
        printf("%02x", ip->tos);
        //case for the display DSCP: CS6 or CS0
        if(ip->tos == 0xc0){
            printf(" (DSCP: CS6,");
            if(ip->tos & 0x10){
                printf(" ECN: CE)\n");
            }
            else{
                printf(" ECN: Not-ECT)\n");
            }
            if(verbose>2){
                printf(" |- 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)\n");
                printf(" |- .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)\n");
            }
        } 
        else if(ip->tos == 0x00){
            printf(" (DSCP: CS0,\n");
            if(ip->tos & 0x10){
                printf(" ECN: CE)\n");
            }
            else{
                printf(" ECN: Not-ECT)\n");
            }
            if(verbose>2){
                printf("     |-0000 00.. = Differentiated Services Codepoint: Class Selector 0 (0)\n");
                printf("     |- .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)\n");
            }
        }
        else{
            printf(" (DSCP: Unknown, ECN: Unknown)\n");
            if(verbose>2){
                printf("     |- Unknown: %02x\n", ip->tos);
            }
        }
        printf(" |- Total Length: %d\n", ntohs(ip->tot_len));
        printf(" |- Identification: 0x%04x\n", ntohs(ip->id));
        printf(" |- Flags:");
        print_flags(flags,verbose);
        printf(" |- Fragment Offset: %d\n", ntohs(ip->frag_off)&0x1FFF);
        printf(" |- Time to live: %d\n", ip->ttl);
        printf(" |- Protocol: "); 
        print_protocol_ip(ip->protocol);
        printf(" (%d)\n", ip->protocol);
        printf(" |- Header checksum: 0x%04x\n", ntohs(ip->check));
        printf(" |- Source Address: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
        printf(" |- Destination Address: %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
        
        printf("\n");
    }
    return ;
}


void print_ipv6(int verbose, struct ip6_hdr *ipv6){
    printf("6, ");
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6->ip6_src), str, INET6_ADDRSTRLEN);
    printf("Src: %s, ", str);
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), str, INET6_ADDRSTRLEN);
    printf("Dst: %s", str);
    printf("\n");

    if(verbose>1){
        printf(" |- 0110 .... = Version: 6\n");
        uint16_t traffic_class = (ipv6->ip6_flow >> 16) & 0xFFF;
        printf(" |- Traffic Class: 0x%02x (", traffic_class);
        if(traffic_class == 0x00){
            printf("DSCP: CS0,");
            if(ipv6->ip6_flow & 0x10){
                printf(" ECN: CE)\n");
            }
            else{
                printf(" ECN: Not-ECT)\n");
            }
            if(verbose>2){
                printf("     |- 0000 00.. = Differentiated Services Codepoint: Default (0)\n");
                printf("     |- .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)\n");
            }
        }
        else if(traffic_class == 0x0E){
            printf("DSCP: CS6,");
            if(ipv6->ip6_flow & 0x10){
                printf(" ECN: CE)\n");
            }
            else{
                printf(" ECN: Not-ECT)\n");
            }
            if(verbose>2){
                printf("     |- 1110 00.. = Differentiated Services Codepoint: Class Selector 6 (48)\n");
                printf("     |- .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)\n");
            }
        }
        else{
            printf("DSCP: Unknown, ECN: Unknown)\n");
            if(verbose>2){
                printf("     |- Unknown: %02x\n", traffic_class);
            }
        }
        uint32_t flow_label = (ipv6->ip6_flow >> 8) & 0x000FFFFF;
        printf(" |- Flow Label: 0x%05x\n", flow_label);
        printf(" |- Payload Length: %d\n", ntohs(ipv6->ip6_plen));
        printf(" |- Next Header: ");
        print_protocol_ip(ipv6->ip6_nxt);
        printf(" (%d)\n", ipv6->ip6_nxt);
        printf(" |- Hop Limit: %d\n", ipv6->ip6_hops);
        printf(" |- Source Address: %s\n", inet_ntop(AF_INET6, &(ipv6->ip6_src), str, INET6_ADDRSTRLEN));
        printf(" |- Destination Address: %s\n", inet_ntop(AF_INET6, &(ipv6->ip6_dst), str, INET6_ADDRSTRLEN));
        printf("\n");
    }
    
    return ;
}

int ip(const unsigned char* packet, int verbose){
    

   uint16_t version = (packet[12] << 8) | packet[13];
   int next_protocol = 0;
    printf("Internet Protocol Version "); 
    switch(version){
        case 0x0800:
            struct iphdr *ipv4 = (struct iphdr*)(packet + sizeof(struct ether_header));
            u_int16_t flags = ntohs(ipv4->frag_off);
            print_ipv4(verbose, ipv4, flags); 
            next_protocol = ipv4->protocol;
            break;
        case 0x86DD:
            struct ip6_hdr *ipv6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
            print_ipv6(verbose, ipv6);
            next_protocol = ipv6->ip6_nxt;
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("\n");
    return next_protocol;
}