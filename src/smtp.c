#include "smtp.h"


void print_response_code(int value){
    printf("<domain> ");
    switch(value){
        case 211:
            printf("System status, or system help reply (211)\n");
            break;
        case 214:
            printf("Help message (214)\n");
            break;
        case 220:
            printf("Service ready (220)\n");
            break;
        case 221:
            printf("Service closing transmission channel (221)\n");
            break;
        case 250:
            printf("Requested mail action okay, completed (250)\n");
            break;
        case 251:
            printf("User not local; will forward to <forward-path> (251)\n");
            break;
        case 354:
            printf("Start mail input; end with <CRLF>.<CRLF> (354)\n");
            break;
        case 421:
            printf("Service not available, closing transmission channel (421)\n");
            break;
    }
}


void print_smtp(const unsigned char* packet, int verbose){
    printf("Simple Mail Transfer Protocol\n");
    //I don't find a lot of packet to test my code, so i use this packets to test my code. It print normally this for the response packet:
    // |- Reponse: 250 OK\r\n
    // |- Response code: <domain> Requested mail action okay, completed (250)
    // |- Response parameter: OK
    // |- Response parameter: SIZE 35882577
    // |- Response parameter: mx.google.com at your service, [108.39.81.51]
    //If you want to test this code, you can uncomment this packet.
    /*packet=(const unsigned char[]) {0x32, 0x35, 0x30, 0x20, 0x4F, 0x4B, 0x0D, 0x0A, 0x32, 0x35, 0x30,0x2d,
    0x53, 0x49, 0x5a,0x45,0x20,0x33,0x35,0x38,0X38,0x32,0x35,0x37,0x37,0x0d,0x0a,0x32,0x35,0x30,0x2d,0x6d, 
    0x78, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x61, 0x74, 0x20,
    0x79, 0x6f, 0x75, 0x72, 0x20, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2c, 0x20, 0x5b, 0x31, 0x30,
    0x38, 0x2e, 0x33, 0x39, 0x2e, 0x38, 0x31, 0x2e, 0x35, 0x31, 0x5d,0x0d,0x0a};*/

    //And for the command packet this: 
    // |- Command Line: quit\r\n
    // |- Command: quit
    /*packet=(const unsigned char[]) {0x71, 0x75, 0x69, 0x74, 0x0d, 0x0a};*/


    const unsigned char* packetv3 = packet;
    int smtpResponseCode = (packet[0] - 48) * 100 + (packet[1] - 48) * 10 + (packet[2] - 48);
    if(verbose>=2){
        if(smtpResponseCode >=100 && smtpResponseCode <=999){
            printf(" |- Reponse: %d", smtpResponseCode);
            packet+=3;
        }
        else{
            printf(" |- Command Line: ");
        }
        while(*packet!= 0x0d && *(packet+1)!= 0x0a && *(packet+2)!=0x32){
            if(*packet==0x0d && *(packet+1)==0x0a){
                printf("\\r\\n");
                printf("\n");
                printf(" |- ");
                packet += 2;
            }
            if(isprint(*packet)){
                printf("%c",*packet);
            }
            else{
                printf(".");
            }
            packet++;
        }
        printf("\\r\\n");
        printf("\n");
    }
    if(verbose==3){
        if(smtpResponseCode >=100 && smtpResponseCode <=999){
            printf("     |- Response code: ");
            print_response_code(smtpResponseCode);
            printf("     |- Response parameter: ");
            packetv3+=4;
            while(1){
                if(*packetv3==0x0d && *(packetv3+1)==0x0a && *(packetv3+2)==0x32){
                    printf("\n");
                    printf("     |- Response parameter: ");
                    packetv3 += 6;
                }
            
                if(*packetv3==0x0d && *(packetv3+1)==0x0a){
                    break;
                }
                if(isprint(*packetv3)){
                    printf("%c",*packetv3);
                }
                else{
                    printf(".");
                }
                packetv3++;
            }
            printf("\n");
        }
        else{
            printf("     |- Command: ");
            while(1){
                if(*packetv3==0x0d && *(packetv3+1)==0x0a){
                    break;
                }
                if(isprint(*packetv3)){
                    printf("%c",*packetv3);
                }
                else{
                    printf(".");
                }
                packetv3++;
            }
        }
    }
}

void smtp(const unsigned char* packet, int verbose, int type, uint16_t *option_length){
    switch(type){
        case 4:
            const unsigned char* data = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + *option_length;
            if(*data==0x00){
                return;
            }
            print_smtp(data, verbose);
            break;
        case 6:
            const unsigned char* datav6 = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + *option_length;
            if(*datav6==0x00){
                return;
            }
            print_smtp(datav6, verbose);
            break;
    }
    printf("\n");

}