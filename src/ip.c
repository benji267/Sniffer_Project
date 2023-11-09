#include "ip.h"



void print_protocol_ip(int protocol){
    switch(protocol){
        case IPPROTO_ICMP:
            printf("ICMPV4\n");
            break;
        case IPPROTO_ICMPV6:
            printf("ICMPV6\n");
            break;
        case IPPROTO_TCP:
            printf("TCPV4\n");
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    return ;
}

void print_flags(u_int16_t flags){
    if(flags & IP_DF){
        printf("DF (Don't Fragment) \n");
    }
    if(flags & IP_MF){
        printf("MF (More Fragments)\n ");
    }
    if(flags & IP_RF){
        printf("RF (Reserved Flag)\n ");
    }
    return ;
}


void print_ipv4(int verbose, struct iphdr *ip,u_int16_t flags){
    printf("IPV4: \n");
    printf("Source: %s -> ", inet_ntoa(*(struct in_addr*)&ip->saddr));
    printf("Destination: %s, ", inet_ntoa(*(struct in_addr*)&ip->daddr));
    printf("Following Protocol: ");
    print_protocol_ip(ip->protocol);
    printf("\n");

    if(verbose>1){
        printf("IHL: %d\n", ip->ihl);
        printf("Type of Service: %d\n", ip->tos);
        printf("Total Length: %d\n", ntohs(ip->tot_len));
        printf("Identification: %d\n", ntohs(ip->id));
        printf("\n");
    }

    if(verbose>2){
        printf("Flags : ");
        print_flags(flags);
        printf("Fragment Offset: %d\n", ntohs(ip->frag_off));
        printf("TTL: %d\n", ip->ttl);
        printf("Checksum: %d\n", ntohs(ip->check));
        printf("\n");
    }
    return ;
}


void print_ipv6(int verbose, struct ip6_hdr *ipv6){
    printf("IPV6: \n");
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6->ip6_src), str, INET6_ADDRSTRLEN);
    printf("Source: %s ->", str);
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), str, INET6_ADDRSTRLEN);
    printf("Destination: %s, ", str);
    printf("Following Protocol: ");
    print_protocol_ip(ipv6->ip6_nxt);
    printf("\n");

    if(verbose>1){
        printf("Version: %d\n", ipv6->ip6_vfc);
        printf("Traffic Class: %d\n", ipv6->ip6_flow);
        printf("Payload Length: %d\n", ntohs(ipv6->ip6_plen));
        printf("Hop Limit: %d\n", ipv6->ip6_hops);
        printf("\n");
    }

    if(verbose>2){
        printf("Flow Label: %d\n", ipv6->ip6_flow);
        printf("\n");
    }
    return ;
}

int ip(const unsigned char* packet, int verbose){
    

   uint16_t version = (packet[12] << 8) | packet[13];
   int next_protocol = 0;
    printf("Protocole IP: "); 
    switch(version){
        case 0x0800:
            struct iphdr *ipv4 = (struct iphdr*)(packet + sizeof(struct ether_header));
            u_int16_t flags = ntohs(ipv4->frag_off);
            print_ipv4(verbose, ipv4, flags); 
            next_protocol = ipv4->protocol;
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        case 0x86DD:
            struct ip6_hdr *ipv6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
            print_ipv6(verbose, ipv6);
            next_protocol = ipv6->ip6_nxt;
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        default:
            printf("Unknown\n");
            break;
    }
    return next_protocol;
}