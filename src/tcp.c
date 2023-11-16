#include "tcp.h"

int print_application(int source, int destination){
    if(source == TELNET || destination==TELNET){
        printf("Application: Telnet\n");
        return TELNET;
    }
    return -1;
}


void print_optionv4(const unsigned char *packet,uint8_t offset,uint16_t *total_options_length){
    const unsigned char *option = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    uint8_t kind, length;
    while(option < packet + sizeof(struct ether_header) + sizeof(struct iphdr) + offset){
        kind = *option;
        switch(kind){

            case 0:
                printf("%d End of Option List (EOL)\n", kind);
                break;
            
            case 1:
                printf("%d No-Operation (NOP)\n", kind);
                *total_options_length+=1;
                break;

            case 2: 
                printf("%d Maximum Segment Size (MSS)\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                printf("MSS Value: %d\n", ntohs(*(uint16_t*)(option + 2)));
                option+=LENMAXSEG-1;
                *total_options_length+=length;
                break;
            
            case 3:

                printf("%d Window Scale (WSS)\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                printf("Shift Count: %d\n", *(option + 2));
                option+=LENWINDOW-1;
                *total_options_length+=length;
                break;
            
            case 4:

                printf("%d SACK Permitted Option\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                option+=LEN_SACK_PERMITTED-1;
                *total_options_length+=length;
                break;
            
            case 5:
                    
                    printf("%d SACK Option\n", kind);
                    length = *(option + 1);
                    printf("Length: %d\n", length);
                    *total_options_length+=length;
                    break;
                
            case 8:
                printf("%d Timestamps Option\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                printf("Timestamp Value: %d\n", ntohl(*(uint32_t*)(option + 2)));
                printf("Timestamp Echo Reply: %d\n", ntohl(*(uint32_t*)(option + 6)));
                option+=LEN_TIMESTAMP-1;
                *total_options_length+=length;
                break;
            
            default:
                printf("%d Unknown\n", kind);
                break;
        }
        option++;
    }
    printf("Total Options Length: %d bytes\n", *total_options_length);
}
    
void print_optionv6(const unsigned char *packet,uint8_t offset,uint16_t *total_options_length){
    const unsigned char *option = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
    uint8_t kind, length;
    while(option < packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + offset){
        kind = *option;
        switch(kind){

            case 0:
                printf("%d End of Option List (EOL)\n", kind);
                break;
            
            case 1:
                printf("%d No-Operation (NOP)\n", kind);
                *total_options_length+=1;
                break;

            case 2: 
                printf("%d Maximum Segment Size (MSS)\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                printf("MSS Value: %d\n", ntohs(*(uint16_t*)(option + 2)));
                option+=LENMAXSEG-1;
                *total_options_length+=length;
                break;
            
            case 3:

                printf("%d Window Scale (WSS)\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                printf("Shift Count: %d\n", *(option + 2));
                option+=LENWINDOW-1;
                *total_options_length+=length;
                break;
            
            case 4:

                printf("%d SACK Permitted Option\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                option+=LEN_SACK_PERMITTED-1;
                *total_options_length+=length;
                break;
            
            case 5:
                    
                    printf("%d SACK Option\n", kind);
                    length = *(option + 1);
                    printf("Length: %d\n", length);
                    *total_options_length+=length;
                    break;
                
            case 8:
                printf("%d Timestamps Option\n", kind);
                length = *(option + 1);
                printf("Length: %d\n", length);
                printf("Timestamp Value: %d\n", ntohl(*(uint32_t*)(option + 2)));
                printf("Timestamp Echo Reply: %d\n", ntohl(*(uint32_t*)(option + 6)));
                option+=LEN_TIMESTAMP-1;
                *total_options_length+=length;
                break;
            
            default:
                printf("%d Unknown\n", kind);
                break;
        }
        option++;
    }
    printf("Total Options Length: %d bytes\n", *total_options_length);
}





int print_tcpv4(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header, uint16_t *options_length){
    int application;
    printf("Source Port: %d -> ", ntohs(tcp_header->source));
    printf("Destination Port: %d\n", ntohs(tcp_header->dest));
    printf("\n");

    if(verbose>1){
        printf("Sequence Number: %d\n", ntohl(tcp_header->seq));
        printf("Acknowledgment Number: %d\n", ntohl(tcp_header->ack_seq));
        printf("Data Offset: %d\n", tcp_header->doff);
        printf("Reserved: %d\n", tcp_header->res1);
        printf("NS: %d\n", tcp_header->res2);
        printf("Window Size: %d\n", ntohs(tcp_header->window));
        printf("Checksum: 0x%x\n", ntohs(tcp_header->check));
        printf("Urgent Pointer: %d\n", ntohs(tcp_header->urg_ptr));
        printf("\n");
    }

    if(verbose>2){
        printf("Flags: 0x%x\n", tcp_header->th_flags);
        printf ("URG=%x, ACK=%x, PSH=%x, RST=%x, SYN=%x, FIN=%x\n", tcp_header->urg, tcp_header->ack, tcp_header->psh, tcp_header->rst, tcp_header->syn, tcp_header->fin);
        if(tcp_header->doff > 5){
            printf("Options: \n");
            print_optionv4(packet, tcp_header->doff*4, options_length);
        }
        application=print_application(ntohs(tcp_header->source), ntohs(tcp_header->dest));
        printf("\n");

    }


    return application;
}

int print_tcpv6(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header, uint16_t *options_length){
    int application;
    printf("Source Port: %d -> ", ntohs(tcp_header->source));
    printf("Destination Port: %d\n", ntohs(tcp_header->dest));
    printf("\n");

   if(verbose>1){
        printf("Sequence Number: %d\n", ntohl(tcp_header->seq));
        printf("Acknowledgment Number: %d\n", ntohl(tcp_header->ack_seq));
        printf("Data Offset: %d\n", tcp_header->doff);
        printf("Reserved: %d\n", tcp_header->res1);
        printf("NS: %d\n", tcp_header->res2);
        printf("Window Size: %d\n", ntohs(tcp_header->window));
        printf("Checksum: 0x%x\n", ntohs(tcp_header->check));
        printf("Urgent Pointer: %d\n", ntohs(tcp_header->urg_ptr));
        printf("\n");
    }

    if(verbose>2){
        printf("Flags: 0x%x\n", tcp_header->th_flags);
        printf ("URG=%x, ACK=%x, PSH=%x, RST=%x, SYN=%x, FIN=%x\n", tcp_header->urg, tcp_header->ack, tcp_header->psh, tcp_header->rst, tcp_header->syn, tcp_header->fin);
        if(tcp_header->doff > 5){
            printf("Options: \n");
            print_optionv6(packet, tcp_header->doff*4, options_length);
        }
        application=print_application(ntohs(tcp_header->source), ntohs(tcp_header->dest));
        printf("\n");

    }

    return application;
}


int tcp(const unsigned char* packet, int verbose, int type, uint16_t *options_length){
    int source_port;
    switch(type){
        case 4:
            const struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            printf("Protocol TCPV4: \n");
            source_port=print_tcpv4(packet, verbose, tcp_header, options_length);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;

        case 6:
            const struct tcphdr *tcp_header6 = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            printf("Protocol TCPV6: \n");
            source_port=print_tcpv6(packet, verbose, tcp_header6, options_length);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
    }
    return source_port;
}