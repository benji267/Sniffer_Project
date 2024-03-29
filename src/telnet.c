#include "telnet.h"
#include "telnet_display_functions.h"

void telnet(const unsigned char* packet,int verbose, int type,uint16_t *options_length){
    printf("Telnet Application:\n");
    switch(type){
        case 4:
            
            uint16_t size_telnet = ntohs(((struct iphdr*)(packet + sizeof(struct ether_header)))->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr) - *options_length;
            
            if(verbose>1){
                //Bonus Display the size of the Telnet packet
                printf(" |- Size of Telnet packet: %d\n",size_telnet);
            }            
            printf("\n");

            if(verbose>1){
                const unsigned char* new_packetv2 = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)+*options_length;
                //Create a packet just with the telnet part
                //new_packetv3 will be used to print the telnet number commands and the subcommands that's why I have two pointers.
                const unsigned char* new_packetv3 = packet+sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct tcphdr)+*options_length;
                while(size_telnet>0){
                    //All Telnet commands start with IAC (0xff)
                    if(*new_packetv2 == IAC){
                        printf(" |- IAC: ");
                        new_packetv2++;
                        size_telnet--;
                        print_telnet_commandv2(&new_packetv2,&size_telnet);
                    }
                    //If it's not a Telnet command, I print the character.
                    //because Telnet commands can be a mix of Telnet commands and characters, I have to check if it's a Telnet command or not.
                    else{
                        while(size_telnet>0 && *new_packetv2 != IAC){
                            if(*new_packetv2 == 0x0d){
                                printf("\\r");
                            }
                            else if(*new_packetv2 == 0x0a){
                                printf("\\n");
                            }
                            else{
                                if(isprint(*new_packetv2)){
                                    printf("%c",*new_packetv2);
                                }
                                else{
                                    printf(".");
                                }
                            }
                            new_packetv2++;
                            size_telnet--;
                        }
                    }
                

                if(verbose>2){
                //Create a packet just with the telnet part
                //new_packetv3 will be used to print the telnet number commands and the subcommands
                    if(*new_packetv3 == IAC){
                        new_packetv3++;
                        print_telnet_commandv3(&new_packetv3);
                         printf("\n");
                    }
                    else{
                        new_packetv3++;
                    }
                }
                }
            }

            break;
        case 6:
        //Same as case 4 but I parse the packet differently because ipv6 has not the same length as ipv4.
            uint16_t size_telnetv6 = ntohs(((struct iphdr*)(packet + sizeof(struct ether_header)))->tot_len) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr) - *options_length;

            printf("Size of Telnet packet: %d\n",size_telnetv6);
            printf("\n");

            if(verbose>1){
                const unsigned char* new_packetv2 = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)+*options_length;
                const unsigned char* new_packetv3 = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)+*options_length;
                while(size_telnetv6>0){

                    if(*new_packetv2 == IAC){
                        printf("\n");
                        printf("IAC:\n");
                        new_packetv2++;
                        size_telnetv6--;
                        print_telnet_commandv2(&new_packetv2,&size_telnetv6);
                    }
                    else{
                        while(size_telnetv6>0 && *new_packetv2 != IAC){
                            if(*new_packetv2 == 0x0d){
                                printf("\\r");
                            }
                            else if(*new_packetv2 == 0x0a){
                                printf("\\n");
                            }
                            else{
                                if(isprint(*new_packetv2)){
                                    printf("%c",*new_packetv2);
                                }
                                else{
                                    printf(".");
                                }
                            }
                            new_packetv2++;
                            size_telnetv6--;
                        }
                    }
                

                if(verbose>2){
                    if(*new_packetv3 == IAC){
                        new_packetv3++;
                        print_telnet_commandv3(&new_packetv3);
                         printf("\n");
                    }
                    else{
                        new_packetv3++;
                    }
                }
                }
            }
            break;


        default:
            break;
    }
    printf("\n");
}


