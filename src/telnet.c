#include "telnet.h"



void print_telnet_option(const unsigned char* packet, int verbose){
    const unsigned char* option=packet;
    (void)verbose;
    printf("Option: \n");
    switch(*option){
        case 0x01:
            if(verbose>1){
                printf("Echo\n");
            }
        break;

        case 0x03:
            if(verbose>1){
                printf("Suppress Go Ahead\n");
            }
        break;

        case 0x05:
            if(verbose>1){
                printf("Status\n");
            }
        break;

        case 0x18:
            if(verbose>1){
                printf("Terminal Type\n");
            }
        break;

        case 0x1F:
            if(verbose>1){
                printf("Window Size\n");
            }
        break;

        case 0x20:
            if(verbose>1){
                printf("Terminal Speed\n");
            }
        break;

        case 0x21:
            if(verbose>1){
                printf("Remote Flow Control\n");
            }
        break;
    
        case 0x22:
            if(verbose>1){
                printf("Line mode\n");
            }
        break;

        case 0x23:
            if(verbose>1){
                printf("Environment Option\n");
            }
        break;

        case 0x24:
            if(verbose>1){
                printf("Variable Environment Option\n");
            }
        break;

        case 0x27:
            if(verbose>1){
                printf("New Environment Option\n");
            }
        break;

        default:
            if(verbose>1){
                printf("Unknown\n");
            }
        break;
        
    }
}



void print_telnet_command(const unsigned char* packet, int verbose){
    const unsigned char* command=packet;
    (void)verbose;
    printf("Command: \n");
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
                break;
        }
        command++;
    }
} 

void telnet(const unsigned char* packet,int verbose, int type,uint16_t *options_length){
    printf("Telnet\n");
    const unsigned char* new_packet;
    switch(type){
        case 4:
            new_packet = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)+*options_length;
            if(new_packet[0]== '\r' || new_packet[0]=='\n'){
                printf("\r\\n\n");
            }
            print_telnet_command(new_packet,verbose);
            break;
        case 6:
            new_packet=packet+sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct tcphdr);
            if(new_packet[0]== '\r' || new_packet[0]=='\n'){
                printf("\r\\n\n");
            }
            print_telnet_command(new_packet,verbose);
            break;
        default:
            break;
    }
}

