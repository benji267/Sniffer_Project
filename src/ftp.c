#include "ftp.h"


void print_ftp_command(int type){
    switch(type){
        case FTP_DATA:
            printf("DATA\n");
            break;
        case FTP_CMD_USER:
            printf("USER\n");
            break;
        case FTP_CMD_PASS:
            printf("PASS\n");
            break;
        case FTP_CMD_CWD:
            printf("CWD\n");
            break;
        case FTP_CMD_PWD:
            printf("PWD\n");
            break;
        case FTP_CMD_PORT:
            printf("PORT\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
}

void ftp(const unsigned char* packet, int verbose, int type, uint16_t *option_length){
    printf("File Transfer Protocol\n");
    switch(type){
        case 4:
            packet += sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + *option_length;
            break;
        
        case 6:
            packet += sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + *option_length;
            break;
    }
    
    if(verbose>=2){
        uint8_t ftp_command = *packet;
        packet++;
        printf(" |- FTP Command: ");
        print_ftp_command(ftp_command);
        if(ftp_command == FTP_CMD_PORT){
            printf(" |- FTP Port: %d\n", ntohs(*(uint16_t*)packet));
        }
        else{
            printf(" |- FTP Parameter: ");
            while(1){
                if(*packet==0x0d && *(packet+1)==0x0a){
                    break;
                }
                if(isprint(*packet)){
                    printf("%c",*packet);
                }
                else{
                    printf(".");
                }
                packet++;
            }
            printf("\n");
        }
    }
    return;
}
