#include "tcp.h"

void print_application(int source, int destination){
    if(source == TELNET || destination==TELNET){
        printf("Following Application: Telnet\n");
    }

    else if(source == HTTP || destination==HTTP){
        printf("Following Application: HTTP\n");
    }
    else if(source == POP3 || destination==POP3){
        printf("Following Application: POP3\n");
    }

    else if(source == IMAP || destination==IMAP){
        printf("Following Application: IMAP\n");
    }

    else if(source == DNS || destination==DNS){
        printf("Following Application: DNS\n");
    }
    else{
        printf("Following Application: Unknown\n");
    }

    return ;
    
}

int app_value(int source, int destination){
    if(source == TELNET || destination==TELNET){
        return TELNET;
    }

    else if(source == HTTP || destination==HTTP){
        return HTTP;
    }
    else if(source == POP3 || destination==POP3){
        return POP3;
    }

    else if(source == IMAP || destination==IMAP){
        return IMAP;
    }

    else if(source == DNS || destination==DNS){
        return DNS;
    }
    
    return -1;
}



void print_optionv4(const unsigned char *packet,uint8_t offset,uint16_t *total_options_length, int verbose){
    const unsigned char *option = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    uint8_t kind, length;
    while(option < packet + sizeof(struct ether_header) + sizeof(struct iphdr) + offset){
        
        if(verbose>2){
            printf("TCP Option - ");
        }
        kind = *option;
        switch(kind){

            case 0:
                if(verbose>2){
                    printf("End of Option List (EOL)\n");
                    printf("Kind: EOL (%d)\n", kind);
                }
                break;
            
            case 1:
                if(verbose>2){
                    printf("No-Operation (NOP)\n");
                    printf("Kind: No-Operation (%d)\n", kind);
                }
                *total_options_length+=1;
                break;

            case 2: 
                if(verbose>2){
                    printf("Maximum Segment Size (MSS)\n");
                    printf("Kind: Maximum Segment Size (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                    printf("MSS Value: %d\n", ntohs(*(uint16_t*)(option + 2)));
                }
                option+=LENMAXSEG-1;
                *total_options_length+=length;
                break;
            
            case 3:
                if(verbose>2){
                    printf("Window Scale (WSS)\n");
                    printf("Kind: Window Scale (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                    printf("Shift Count: %d\n", *(option + 2));
                }
                option+=LENWINDOW-1;
                *total_options_length+=length;
                break;
            
            case 4:

                if(verbose>2){
                    printf("SACK Permitted Option\n");
                    printf("Kind: SACK Permitted (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                }
                option+=LEN_SACK_PERMITTED-1;
                *total_options_length+=length;
                break;
            
            case 5:
                    if(verbose>2){
                        printf("SACK Option\n");
                        printf("Kind: SACK (%d)\n", kind);
                    }
                    length = *(option + 1);
                    if(verbose>2){
                        printf("Length: %d\n", length);
                    }
                    *total_options_length+=length;
                    break;
                
            case 8:
                if(verbose>2){
                    printf("Timestamps Option\n");
                    printf("Kind: Timestamps (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                    printf("Timestamp Value: %d\n", ntohl(*(uint32_t*)(option + 2)));
                    printf("Timestamp Echo Reply: %d\n", ntohl(*(uint32_t*)(option + 6)));
                }
                option+=LEN_TIMESTAMP-1;
                *total_options_length+=length;
                break;
            
            default:
                if(verbose>2){
                    printf("%d Unknown\n", kind);
                }
                break;
        }
        printf("\n");
        option++;
    }
    if(verbose>2){
        printf("Total Options Length: %d bytes\n", *total_options_length);
        printf("\n");
    }
}
    
void print_optionv6(const unsigned char *packet,uint8_t offset,uint16_t *total_options_length, int verbose){
    const unsigned char *option = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
    uint8_t kind, length;
    while(option < packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + offset){
        
        if(verbose>2){
            printf("TCP Option - ");
        }
        kind = *option;
        switch(kind){

            case 0:
                if(verbose>2){
                    printf("End of Option List (EOL)\n");
                    printf("Kind: EOL (%d)\n", kind);
                }
                break;
            
            case 1:
                if(verbose>2){
                    printf("No-Operation (NOP)\n");
                    printf("Kind: No-Operation (%d)\n", kind);
                }
                *total_options_length+=1;
                break;

            case 2: 
                if(verbose>2){
                    printf("Maximum Segment Size (MSS)\n");
                    printf("Kind: Maximum Segment Size (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                    printf("MSS Value: %d\n", ntohs(*(uint16_t*)(option + 2)));
                }
                option+=LENMAXSEG-1;
                *total_options_length+=length;
                break;
            
            case 3:
                if(verbose>2){
                    printf("Window Scale (WSS)\n");
                    printf("Kind: Window Scale (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                    printf("Shift Count: %d\n", *(option + 2));
                }
                option+=LENWINDOW-1;
                *total_options_length+=length;
                break;
            
            case 4:

                if(verbose>2){
                    printf("SACK Permitted Option\n");
                    printf("Kind: SACK Permitted (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                }
                option+=LEN_SACK_PERMITTED-1;
                *total_options_length+=length;
                break;
            
            case 5:
                    if(verbose>2){
                        printf("SACK Option\n");
                        printf("Kind: SACK (%d)\n", kind);
                    }
                    length = *(option + 1);
                    if(verbose>2){
                        printf("Length: %d\n", length);
                    }
                    *total_options_length+=length;
                    break;
                
            case 8:
                if(verbose>2){
                    printf("Timestamps Option\n");
                    printf("Kind: Timestamps (%d)\n", kind);
                }
                length = *(option + 1);
                if(verbose>2){
                    printf("Length: %d\n", length);
                    printf("Timestamp Value: %d\n", ntohl(*(uint32_t*)(option + 2)));
                    printf("Timestamp Echo Reply: %d\n", ntohl(*(uint32_t*)(option + 6)));
                }
                option+=LEN_TIMESTAMP-1;
                *total_options_length+=length;
                break;
            
            default:
                if(verbose>2){
                    printf("%d Unknown\n", kind);
                }
                break;
        }
        printf("\n");
        option++;
    }
    if(verbose>2){
        printf("Total Options Length: %d bytes\n", *total_options_length);
        printf("\n");
    }
}





int print_tcpv4(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header, uint16_t *options_length){
    int application;
    printf("%d, ", ntohs(tcp_header->source));
    printf("Dst Port: %d, ", ntohs(tcp_header->dest));
    application=app_value(ntohs(tcp_header->source), ntohs(tcp_header->dest));
    printf("\n");

    if(verbose>1){
        printf(" |- Source Port: %d\n", ntohs(tcp_header->source));
        printf(" |- Destination Port: %d\n", ntohs(tcp_header->dest));
        printf(" |- Sequence Number (raw): %u\n", ntohl(tcp_header->seq));
        printf(" |- Acknowledgment Number (raw): %d\n", ntohl(tcp_header->ack_seq));
        printf(" |- Header Length: %d bytes (%d)\n", tcp_header->doff*4, tcp_header->doff);
        printf(" |- Flags: 0x%03x\n", tcp_header->th_flags);
        if(verbose>2){
            printf("     |- %s%s%s... .... = Reserved: %s\n", tcp_header->res1 & 0x80 ? "1" : "0", tcp_header->res1 & 0x40 ? "1" : "0", tcp_header->res1 & 0x20 ? "1" : "0", tcp_header->res1 & 0x10 ? "Set" : "Not set");
            printf("     |- ...%s .... .... = Accurate ECN: %s\n", tcp_header->res1 & 0x08 ? "1" : "0", tcp_header->res1 & 0x04 ? "Set" : "Not set");
            printf("     |- .... %s... .... = Congestion Window Reduced (CWR): %s\n", tcp_header->res1 & 0x02 ? "1" : "0", tcp_header->res1 & 0x02 ? "Set" : "Not set");
            printf("     |- .... .%s.. .... = ECN-Echo: %s\n", tcp_header->res1 & 0x01 ? "1" : "0", tcp_header->res1 & 0x01 ? "Set" : "Not set");
            printf("     |- .... ..%s. .... = Urgent: %s\n", tcp_header->urg ? "1" : "0", tcp_header->urg ? "Set" : "Not set");
            printf("     |- .... ...%s .... = Acknowledgment: %s\n", tcp_header->ack ? "1" : "0", tcp_header->ack ? "Set" : "Not set");
            printf("     |- .... .... %s... = Push: %s\n", tcp_header->psh ? "1" : "0", tcp_header->psh ? "Set" : "Not set");
            printf("     |- .... .... .%s.. = Reset: %s\n", tcp_header->rst ? "1" : "0", tcp_header->rst ? "Set" : "Not set");
            printf("     |- .... .... ..%s. = Syn: %s\n", tcp_header->syn ? "1" : "0", tcp_header->syn ? "Set" : "Not set");
            printf("     |- .... .... ...%s = Fin: %s\n", tcp_header->fin ? "1" : "0", tcp_header->fin ? "Set" : "Not set");
        }
        printf(" |- Window Size: %d\n", ntohs(tcp_header->window));
        printf(" |- Checksum: 0x%x\n", ntohs(tcp_header->check));
        printf(" |- Urgent Pointer: %d\n", ntohs(tcp_header->urg_ptr));
        if(tcp_header->doff > 5){
            printf(" |- Options: (%ld bytes)\n", (tcp_header->doff*4)-sizeof(struct tcphdr));
        }
        //NB enlever l'option  dans l'appelle d'option j'y ai accès direct au dessus.
        printf("\n");
    }
    //I need the options length in each verbose level so I pass it as a pointer and I put a condition on verbose in the print_option function.
    if(tcp_header->doff > 5){
            print_optionv4(packet, tcp_header->doff*4, options_length,verbose);
        }

    return application;
}

int print_tcpv6(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header, uint16_t *options_length){
    int application;
    printf("Source Port: %d -> ", ntohs(tcp_header->source));
    printf("Destination Port: %d\n", ntohs(tcp_header->dest));
    application=app_value(ntohs(tcp_header->source), ntohs(tcp_header->dest));
    
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
        printf("\n");
        if(tcp_header->doff > 5){
            printf("Options: \n");
            print_optionv6(packet, tcp_header->doff*4, options_length,verbose);
        }
        print_application(ntohs(tcp_header->source), ntohs(tcp_header->dest));
        printf("\n");

    }

    return application;
}


int tcp(const unsigned char* packet, int verbose, int type, uint16_t *options_length){
    int app;
    printf("Transmission Control Protocol, Src Port: ");
    switch(type){
        case 4:
            const struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            app=print_tcpv4(packet, verbose, tcp_header, options_length);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;

        case 6:
            const struct tcphdr *tcp_header6 = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            app=print_tcpv6(packet, verbose, tcp_header6, options_length);
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
    }
    return app;
}