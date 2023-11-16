#include "telnet.h"



void print_telnet(const unsigned char* packet, int verbose){
    const unsigned char* command=packet;
    printf("firs octet: %d\n",*command);
    printf("second octet: %d\n",*(command+1));
    printf("third octet: %d\n",*(command+2));
    /*
    while(command < packet + sizeof(struct tcphdr)){
        switch(*command){
            case NOP:
                printf("No-Operation (NOP)\n");
                break;
            case DM:
                printf("Data Mark (DM)\n");
                break;
            case IP:
                printf("Interrupt Process (IP)\n");
                break;
            case AO:
                printf("Abort Output (AO)\n");
                break;
            case AYT:
                printf("Are You There (AYT)\n");
                break;
            case EC:
                printf("Erase Character (EC)\n");
                break;
            case EL:
                printf("Erase Line (EL)\n");
                break;
            case GA:
                printf("Go Ahead (GA)\n");
                break;
            case SB:
                printf("Subnegotiation (SB)\n");
                break;
            case WILL:
                printf("Will\n");
                break;
            case WONT:
                printf("Won't\n");
                break;
            case DO:
                printf("Do\n");
                break;
            case DONT:
                printf("Don't\n");
                break;
            case IAC:
                printf("Interpret As Command (IAC)\n");
                break;
            default:
                printf("Unknown command\n");
                break;
        }
        command++;
    }*/
} 

void telnet(const unsigned char* packet,int verbose, int type){
    printf("Telnet\n");
    const unsigned char* new_packet;
    switch(type){
        case 4:
            new_packet = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
            print_telnet(new_packet,verbose);
            break;
        case 6:
            new_packet=packet+sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct tcphdr);
            print_telnet(new_packet,verbose);
            break;
        default:
            break;
    }
}

