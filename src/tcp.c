#include "tcp.h"







void print_option(const unsigned char *packet){
    const unsigned char *option = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    printf("Option: \n");
    uint8_t kind/*, length*/;

    while((*option >> 4) * 4 != sizeof(struct tcphdr)){
        kind = *option;
        switch(kind){

            case 0:
                printf("%d End of Option List (EOL)\n", kind);
                break;
            
            case 1:
                printf("%d No-Operation (NOP)\n", kind);
                break;
            
            default:
                printf("%d Unknown\n", kind);
                break;
        }
        option++;
    }
}
    






void print_tcpv4(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header){
    printf("Source Port: %d -> ", ntohs(tcp_header->source));
    printf("Destination Port: %d\n", ntohs(tcp_header->dest));
    
    if(verbose>1){
        printf("Sequence Number: %d\n", ntohl(tcp_header->seq));
        printf("Acknowledgment Number: %d\n", ntohl(tcp_header->ack_seq));
        printf("Data Offset: %d\n", tcp_header->doff);
        printf("Reserved: %d\n", tcp_header->res1);
        printf("NS: %d\n", tcp_header->res2);
        printf("Window Size: %d\n", ntohs(tcp_header->window));
        printf("Checksum: %x\n", ntohs(tcp_header->check));
        printf("Urgent Pointer: %d\n", ntohs(tcp_header->urg_ptr));
    }

    if(verbose>2){
        printf("Flags: \n");
        printf ("URG=%x, ACK=%x, PSH=%x, RST=%x, SYN=%x, FIN=%x\n", tcp_header->urg, tcp_header->ack, tcp_header->psh, tcp_header->rst, tcp_header->syn, tcp_header->fin);
        if(tcp_header->doff > 5){
            printf("Options: \n");
            print_option(packet);
        }
        printf("\n");

    }


    return ;
}

void print_tcpv6(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header){
    return ;
}

void tcp(const unsigned char* packet, int verbose, int type){
    switch(type){
        case 4:
            const struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            printf("Protocol TCPV4: \n");
            print_tcpv4(packet, verbose, tcp_header);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;

        case 6:
            const struct tcphdr *tcp_header6 = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            printf("Protocol TCPV6: \n");
            print_tcpv6(packet, verbose, tcp_header6);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
    }
    return ;
}