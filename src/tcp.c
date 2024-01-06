#include "tcp.h"

//There not a lot of comments because there's a header for tcp so it's common utilisation of the header
//In addition I get almost the same display as wireshark so I don't have weird display.

// Bonus dislay for tcp 
void print_application(int source, int destination){
    if(source == TELNET || destination==TELNET){
        printf(" |- ");
        printf("Following Application: Telnet\n");
    }

    else if(source == HTTP || destination==HTTP){
        printf(" |- ");
        printf("Following Application: HTTP\n");
    }
    else if(source == POP3 || destination==POP3){
        printf(" |- ");
        printf("Following Application: POP3\n");
    }

    else if(source == IMAP || destination==IMAP){   
        printf(" |- ");
        printf("Following Application: IMAP\n");
    }

    else if(source == DNS || destination==DNS){
        printf(" |- ");
        printf("Following Application: DNS\n");
    }
    else if(source == SMTP || destination==SMTP){
        printf(" |- ");
        printf("Following Application: SMTP\n");
    }
    else if(source == FTP || destination==FTP){
        printf(" |- ");
        printf("Following Application: FTP\n");
    }
    else{
        printf(" |- ");
        printf("Following Application: Unknown\n");
    }
    

    return ;
    
}

//need the source and destination port to determine the application
//return the application value for the switch case in the main
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
    else if(source == SMTP || destination==SMTP){
        return SMTP;
    }
    else if(source == FTP || destination==FTP){
        return FTP;
    }
    
    return -1;
}



void print_option(const unsigned char *packet,uint8_t offset, int verbose, int version){
    uint16_t len;
    //Depending on the version, the length of the header is different to get the right offset
    if(version==4){
        len=sizeof(struct iphdr);
    }
    else{
        len=sizeof(struct ip6_hdr);
    }
    const unsigned char *option = packet + sizeof(struct ether_header) + len + sizeof(struct tcphdr);
    uint8_t kind, length;
    while(option < packet + sizeof(struct ether_header) + len + offset){
        // Print the option for each kind
        printf(" |- TCP Option - ");
        kind = *option;
        switch(kind){
            case 0:
                printf("End of Option List (EOL)\n");
                if(verbose>2){ 
                    printf("     |- ");
                    printf("Kind: EOL (%d)\n", kind);
                }
                break;
            
            case 1: 
                printf("No-Operation (NOP)\n");
                if(verbose>2){
                    printf("     |- ");
                    printf("Kind: No-Operation (%d)\n", kind);
                }
                break;

            case 2: 
                printf("Maximum segment size: %d bytes\n", ntohs(*(uint16_t*)(option + 2)));
                if(verbose>2){
                    printf("     |- ");
                    printf("Kind: Maximum Segment Size (%d)\n", kind);
                    length = *(option + 1);
                    printf("     |- ");
                    printf("Length: %d\n", length);
                    printf("     |- ");
                    printf("MSS Value: %d\n", ntohs(*(uint16_t*)(option + 2)));
                }
                option+=LENMAXSEG-1;
                break;
            
            case 3:
                printf("Window Scale: %d\n", (*(option + 2)));
                if(verbose>2){
                    printf("     |- ");
                    printf("Kind: Window Scale (%d)\n", kind);
                    length = *(option + 1);
                    printf("     |- ");
                    printf("Length: %d\n", length);
                    printf("     |- ");
                    printf("Shift count: %d\n", *(option + 2));
                }
                option+=LENWINDOW-1;
                break;
            
            case 4:
                printf("SACK Permitted Option\n");
                if(verbose>2){
                    printf("     |- ");
                    printf("Kind: SACK Permitted (%d)\n", kind);
                    length = *(option + 1);
                    printf("     |- ");
                    printf("Length: %d\n", length);
                }
                option+=LEN_SACK_PERMITTED-1;
                break;
            
            case 5:
                    printf("SACK Option\n");
                    if(verbose>2){
                        printf("     |- ");
                        printf("Kind: SACK (%d)\n", kind);
                        length = *(option + 1);
                        printf("     |- ");
                        printf("Length: %d\n", length);
                    }
                    break;
                
            case 8:
                printf("Timestamps\n");
                if(verbose>2){
                    printf("     |- ");
                    printf("Kind: Timestamps (%d)\n", kind);
                    length = *(option + 1);
                    printf("     |- ");
                    printf("Length: %d\n", length);
                    printf("     |- ");
                    printf("Timestamp Value: %d\n", ntohl(*(uint32_t*)(option + 2)));
                    printf("     |- ");
                    printf("Timestamp Echo Reply: %d\n", ntohl(*(uint32_t*)(option + 6)));
                }
                option+=LEN_TIMESTAMP-1;
                break;
            
            default:
                printf("%d Unknown\n", kind);
                
                break;
        }
        printf("\n");
        option++;
    }
}
    






int print_tcp(const unsigned char* packet, int verbose,const struct tcphdr* tcp_header, uint16_t *options_length, int version){
    int application;
    printf("%d, ", ntohs(tcp_header->source));
    printf("Dst Port: %d, ", ntohs(tcp_header->dest));
    application=app_value(ntohs(tcp_header->source), ntohs(tcp_header->dest));
    printf("\n");

    if(verbose>1){
        //Without the ISN I can't calculate the sequence number
        //This ISN is the first sequence number of the connection and I analyse each packet independently
        //So I print the raw value of the sequence number, ack number.
        printf(" |- Source Port: %d\n", ntohs(tcp_header->source));
        printf(" |- Destination Port: %d\n", ntohs(tcp_header->dest));
        printf(" |- Sequence Number (raw): %u\n", ntohl(tcp_header->seq));
        printf(" |- Acknowledgment Number (raw): %d\n", ntohl(tcp_header->ack_seq));
        printf(" |- Header Length: %d bytes (%d)\n", tcp_header->doff*4, tcp_header->doff);
        printf(" |- Flags: 0x%03x\n", tcp_header->th_flags);
        if(verbose>2){
            //Some ternary operator to print the flags and to simplify the code (without further if condition)
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
        printf(" |- Checksum: 0x%x\n", ntohs(tcp_header->th_sum));
        printf(" |- Urgent Pointer: %d\n", ntohs(tcp_header->urg_ptr));
        //If the header length is greater than 5, there are options and I print them
        if(tcp_header->doff > 5){
            printf(" |- Options: (%ld bytes)\n", tcp_header->doff*4-sizeof(struct tcphdr));
            print_option(packet, tcp_header->doff*4,verbose, version);
        }

        print_application(ntohs(tcp_header->source), ntohs(tcp_header->dest));
    }
    *options_length+=tcp_header->doff*4-sizeof(struct tcphdr);
    return application;
}




int tcp(const unsigned char* packet, int verbose, int type, uint16_t *options_length){
    int app;
    printf("Transmission Control Protocol, Src Port: ");
    //As always, depending on the version, the offset is different and to parse perfectly the packet, I need to know the version .
    switch(type){
        case 4:
            const struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            app=print_tcp(packet, verbose, tcp_header, options_length, type);
            break;

        case 6:
            const struct tcphdr *tcp_header6 = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            app=print_tcp(packet, verbose, tcp_header6, options_length, type);
            break;
    }
    printf("\n");
    return app;
}