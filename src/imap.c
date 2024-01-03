#include "imap.h"

void imap(const unsigned char* packet, int verbose, int type, uint16_t *option_length){
    printf("IMAP\n");
    const unsigned char* payload;
    switch(type){
        case 4:
            payload= packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
            break;
        case 6:
            payload= packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
            break;
    }
    if(verbose==2){
        printf(" |- ");
        while(*payload!= 0x0d && *(payload+1)!= 0x0a){
            if(isprint(*payload)){
                printf("%c",*payload);
            }
            else{
                printf(".");
            }
            payload++;
        }
        printf("\\r\\n");
        printf("\n");
    }
    if(verbose==3){
        printf(" |- ");
        while(*payload!= 0x0d && *(payload+1)!= 0x0a && *(payload+2)!= 0x0d && *(payload+3)!= 0x0a){
            if(*payload==0x0d && *(payload+1)==0x0a){
                printf("\\r\\n");
                printf("\n");
                printf("     |- ");
            }
            if(isprint(*payload)){
                printf("%c",*payload);
            }
            else{
                printf(".");
            }
            payload++;
        }
        printf("\\r\\n");
        printf("\n");
        printf("\\r\\n");
        printf("\n");        
    }
    return ;
}