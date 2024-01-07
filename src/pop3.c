#include "pop3.h"


void pop3(const unsigned char* packet, int verbose, int type, uint16_t *option_length){
    printf("POP3 Application:\n");
    //Only 2 verbose levels for POP3 because there is not a lot of information to display.
    if(verbose>1){
        printf(" |-");
        int i;
        const unsigned char* packet2;
        switch(type){
            case 4:
                i=0;
                packet2=packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + *option_length;
                //POP3 finish with 0D 0A 2E 0D 0A sequence
                while(*packet2 != 0x0D || *(packet2+1) != 0x0A || *(packet2+2) != 0x2E || *(packet2+3) != 0x0D || *(packet2+4) != 0x0A){
                    if(i!=0 && i%80==0){
                        printf("\n");
                    }
                    if(isprint(*packet2)){
                        printf("%c",*packet2);
                    }
                    else{
                        printf(".");
                    }
                    i++;
                    packet2++;
                }

                printf("\n");
                break;

            case 6:
                i=0;
                packet2=packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + *option_length;
                //POP3 finish with 0D 0A 2E 0D 0A sequence
                while(*packet2 != 0x0D || *(packet2+1) != 0x0A || *(packet2+2) != 0x2E || *(packet2+3) != 0x0D || *(packet2+4) != 0x0A){
                    if(i!=0 && i%80==0){
                        printf("\n");
                    }
                    if(isprint(*packet2)){
                        printf("%c",*packet2);
                    }
                    else{
                        printf(".");
                    }
                    i++;
                    packet2++;
                }
                printf("\n");
                break;
            default:
                break;
        }
    }
}