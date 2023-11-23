#include "http.h"


void http(const unsigned char* packet, int verbose, int type,uint16_t *option_length){
    printf("HyperText Transfer Protocol:");
    printf("\n");
    uint16_t size_http;
    size_http = ntohs(((struct iphdr*)(packet + sizeof(struct ether_header)))->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr) - *option_length;
    printf("Size of HTTP packet: %d\n",size_http);
    printf("\n");
    
    switch(type){
        case 4:
            if(verbose>=2){
                bool first_return = false;
                const unsigned char* new_packet = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)+*option_length;
                while(new_packet < packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size_http){
                    //If the following packet is a XML packet, I stop the loop.
                    if(*new_packet==0x3c && *(new_packet+1)==0x21){
                        break;
                    }
                    //If the following packet is a HTML packet, I stop the loop.
                    else if(*new_packet == 0x68 && *(new_packet+1) == 0x74 && *(new_packet+2) == 0x6d && *(new_packet+3) == 0x6c && *(new_packet+4) == 0x3e){
                        break;
                    } 
                    //If the following packet is a JSON packet, I stop the loop.
                    else if(*new_packet==0x7b){
                        break;
                    }

                    else if(*new_packet == 0x0d && *(new_packet+1) == 0x0a && *(new_packet+2) == 0x0d && *(new_packet+3) == 0x0a){
                            printf("\\r\\n");
                            printf("\n");
                            printf("\\r\\n");
                            printf("\n");
                            new_packet+=3;
                          
                    }
                    else if(*new_packet == 0x0d && *(new_packet+1) == 0x0a){
                        printf("\\r\\n");
                        printf("\n");
                        
                        //For level 2 I use a boolean to print only the first line of the HTTP packet with the request.
                        if(!first_return && verbose==2){
                            first_return = true;
                            break;
                        }
                        new_packet++;
                    }
                    else if(*new_packet == 0x0d){
                        printf("\\r");
                    }
                    else if(*new_packet == 0x0a){
                        printf("\\n");
                    }
                    else{
                        if(isprint(*new_packet)){
                            printf("%c",*new_packet);
                        }
                        else{
                            printf(".");
                        }
                    }
                    new_packet++;
                }
                printf("\n");

            }
            break;
        
        case 6:
           if(verbose>=2){
                bool first_return = false;
                const unsigned char* new_packet = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)+*option_length;
                while(new_packet < packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + size_http){
                    if(*new_packet==0x3c && *(new_packet+1)==0x21){
                        break;
                    }
                    else if(*new_packet == 0x0d && *(new_packet+1) == 0x0a && *(new_packet+2) == 0x0d && *(new_packet+3) == 0x0a){
                            printf("\\r\\n");
                            printf("\n");
                            printf("\\r\\n");
                            printf("\n");
                            new_packet+=3;
                          
                    }
                    else if(*new_packet == 0x0d && *(new_packet+1) == 0x0a){
                        printf("\\r\\n");
                        printf("\n");
                        
                        //For level 2 I use a boolean to print only the first line of the HTTP packet with the request.
                        if(!first_return && verbose==2){
                            first_return = true;
                            break;
                        }
                        new_packet++;
                    }
                    else if(*new_packet == 0x0d){
                        printf("\\r");
                    }
                    else if(*new_packet == 0x0a){
                        printf("\\n");
                    }
                    else{
                        if(isprint(*new_packet)){
                            printf("%c",*new_packet);
                        }
                        else{
                            printf(".");
                        }
                    }
                    new_packet++;
                }
                printf("\n");

            }
            break;
    }

    for(int i=0;i<6;i++){
        printf("\n");
    }

    
}