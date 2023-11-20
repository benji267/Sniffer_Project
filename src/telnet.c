#include "telnet.h"
#include "telnet_display_functions.h"

void telnet(const unsigned char* packet,int verbose, int type,uint16_t *options_length){
    printf("Telnet Application:\n");
    const unsigned char* new_packet;
    switch(type){
        case 4:
            
            //Create a packet just with the telnet part
            new_packet = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)+*options_length;
            uint16_t size_telnet = ntohs(((struct iphdr*)(packet + sizeof(struct ether_header)))->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr) - *options_length;

            printf("Size of Telnet packet: %d\n",size_telnet);
            //Print the telnet part. I have size_telnet*3 because I have to print the IAC, the command and the option.
            while(new_packet < packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size_telnet*3){
                if(verbose>1){
                    if(*new_packet == IAC){
                        printf("IAC:\n ");
                        new_packet++;
                        print_telnet_command(new_packet,verbose);
                    }
                    else{
                        new_packet++;
                    }

                }

                if(verbose>2){}

            }
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        case 6:
            new_packet=packet+sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct tcphdr);
            print_telnet_command(new_packet,verbose);
            break;
        default:
            break;
    }
}


