#include "http.h"


void http(const unsigned char* packet, int verbose, int type,uint16_t *option_length){
    printf("HyperText Transfer Protocol:\n");
    printf("\n");
    uint16_t size_http;
    
    switch(type){
        case 4:
            if(verbose>1){
                size_http = ntohs(((struct iphdr*)(packet + sizeof(struct ether_header)))->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr) - *option_length;
                printf("Size of HTTP packet: %d\n",size_http);
                printf("\n");
            }
            
            if(verbose>2){
                const unsigned char* new_packetv = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)+*option_length;
                while(new_packetv < packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size_http){
                    if(*new_packetv == 0x0d && *(new_packetv+1) == 0x0a && *(new_packetv+2) == 0x0d && *(new_packetv+3) == 0x0a){
                            printf("\\r\\n");
                            printf("\n");
                            printf("\\r\\n");
                            printf("\n");
                            printf("Data: ");
                            new_packetv++;
                    }
                    else if(*new_packetv == 0x0d && *(new_packetv+1) == 0x0a){
                        printf("\\r\\n");
                        printf("\n");
                        new_packetv++;
                    }
                    else if(*new_packetv == 0x0d){
                        printf("\\r");
                    }
                    else if(*new_packetv == 0x0a){
                        printf("\\n");
                    }
                    else{
                        if(isprint(*new_packetv)){
                            printf("%c",*new_packetv);
                        }
                        else{
                            printf(".");
                        }
                    }
                    new_packetv++;
                }
                printf("\n");

            }
            break;
        
        case 6:
            if(verbose>1){
                size_http = ntohs(((struct ip6_hdr*)(packet + sizeof(struct ether_header)))->ip6_plen) - sizeof(struct tcphdr) - *option_length;
                printf("Size of HTTP packet: %d\n",size_http);
                printf("\n");
            }

            if(verbose>2){
                 const unsigned char* new_packetv6 = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)+*option_length;
                while(new_packetv6 < packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + size_http){
                    if(*new_packetv6 == 0x0d && *(new_packetv6+1) == 0x0a){
                        printf("\\r\\n");
                        printf("\n");
                        new_packetv6++;
                    }
                    else if(*new_packetv6 == 0x0d){
                        printf("\\r");
                    }
                    else if(*new_packetv6 == 0x0a){
                        printf("\\n");
                    }
                    else{
                        printf("%c",*new_packetv6);
                    }
                    new_packetv6++;
                }
                printf("\n");

            }
            break;
    }

    for(int i=0;i<6;i++){
        printf("\n");
    }

    
}