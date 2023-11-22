#include "telnet.h"
#include "telnet_display_functions.h"

void telnet(const unsigned char* packet,int verbose, int type,uint16_t *options_length){
    printf("Telnet Application:\n");
    const unsigned char* new_packetv2;
    const unsigned char* new_packetv3;
    switch(type){
        case 4:
            
            //Create a packet just with the telnet part
            new_packetv2 = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)+*options_length;
            new_packetv3 = packet+sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct tcphdr)+*options_length;
            uint16_t size_telnet = ntohs(((struct iphdr*)(packet + sizeof(struct ether_header)))->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr) - *options_length;

            printf("Size of Telnet packet: %d\n",size_telnet);
            printf("\n");
            //Print the telnet part. I have size_telnet*3 because I have to print the IAC, the command and the option.
            while(new_packetv2 < packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size_telnet*3){
                if(verbose==1){
                    break;
                }

                if(verbose>1){
                    if(*new_packetv2 == IAC){
                        printf("IAC:\n");
                        new_packetv2++;
                        print_telnet_commandv2(&new_packetv2);
                    }
                    else{/*
                        printf("Data: ");
                        while(new_packetv2 < packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size_telnet * 3 && *new_packetv2 != IAC){
                            if(*new_packetv2 == 0x0d){
                                printf("\\r");
                            }
                            else if(*new_packetv2 == 0x0a){
                                printf("\\n");
                            }
                            else{
                                printf("%c",*new_packetv2);
                            }*/
                            new_packetv2++;
                        //}
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

                
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;
        case 6:
            new_packetv2=packet+sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct tcphdr);
            new_packetv3=packet+sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct tcphdr);
            uint16_t size_telnetv6 = ntohs(((struct ip6_hdr*)(packet + sizeof(struct ether_header)))->ip6_ctlun.ip6_un1.ip6_un1_plen) - sizeof(struct tcphdr);

            printf("Size of Telnet packet: %d\n",size_telnetv6);
            printf("\n");
            print_telnet_commandv2(&new_packetv2);
            
            while(new_packetv2 < packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + size_telnetv6*3){
                if(verbose==1){
                    break;
                }

                if(verbose>1){
                    if(*new_packetv2 == IAC){
                        printf("IAC:\n");
                        new_packetv2++;
                        print_telnet_commandv2(&new_packetv2);
                    }
                    else{/*
                        printf("Data: ");
                        while(new_packetv2 < packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + size_telnet * 3 && *new_packetv2 != IAC){
                            if(*new_packetv2 == 0x0d){
                                printf("\\r");
                            }
                            else if(*new_packetv2 == 0x0a){
                                printf("\\n");
                            }
                            else{
                                printf("%c",*new_packetv2);
                            }*/
                            new_packetv2++;
                        //}
                    }
                }

                if(verbose>2){
                    if(*new_packetv3 == IAC){
                        new_packetv3++;
                        print_telnet_commandv3(&new_packetv3);
                    }
                    else{
                        new_packetv3++;
                    }
                }
                printf("\n");

            }
                
            for(int i=0;i<6;i++){
                printf("\n");
            }
            break;


        default:
            break;
    }
}


