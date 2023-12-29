#include "dns.h"



void print_answer(const unsigned char* packet,uint16_t type,int data_length){
    switch(type){
        case 1:
            printf("addr ");
            for(int i=0;i<data_length;i++){
                printf("%u",packet[i]);
                if(i!=data_length-1){
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 2:
            printf("name server");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 3:
            printf("mail destination ");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 4:
            printf("mail forwarder ");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 5:
            printf("cname ");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 6:
            printf("primary name server ");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 12:
            printf("ptr ");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 15:
            printf("mail exchange ");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 16:
            printf("txt ");
            for(int i=0;i<data_length;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
            }
            printf("\n");
            break;

        case 28:
            printf("addr ");
            for(int i=0;i<data_length;i++){
                printf("%x",packet[i]);
                if(i!=data_length-1){
                    printf(":");
                }
            }
            printf("\n");
            break;
        case 251:
            printf("ixfr ");
            for(int i=0;i<data_length;i++){
                printf("%x",packet[i]);
                if(i!=data_length-1){
                    printf(":");
                }
            }
            printf("\n");
            break;
        case 252:
            printf("axfr ");
            for(int i=0;i<data_length;i++){
                printf("%x",packet[i]);
                if(i!=data_length-1){
                    printf(":");
                }
            }
            printf("\n");
            break;
        default:
            printf("Unknown");
            break;
    }
    return ;
}

void print_classv3(uint16_t class){
    switch(class){
        case 1:
            printf("IN (0x000%x)",class);
            break;
        case 2: 
            printf("CS (0x00%x)",class);
            break;
        case 3:
            printf("CH (0x00%x)",class);
            break;
        case 4:
            printf("HS (0x00%x)",class);
            break;
        default:
            printf("Unknown");
            break;
    }
    printf("\n");
    return ;
}



void print_typev3(const unsigned char* packet,uint16_t type){
    switch(type){
        case 1:
            printf("A (%x) (Host Address)",*packet);
            break;
        case 2:
            printf("NS (%x) (Authoritative Name Server)",*packet);
            break;
        case 3:
            printf("MD (%x) (Mail Destination)",*packet);
            break;
        case 4:
            printf("MF (%x) (Mail Forwarder)",*packet);
            break;
        case 5:
            printf("CNAME (%x) (Canonical NAME for an alias)",*packet);
            break;
        case 6:
            printf("SOA (%x) (Start Of Authority)",*packet);
            break;
        case 12:
            printf("PTR (%x) (Domain Name Pointer)",*packet);
            break;
        case 15:
            printf("MX (%x) (Mail Exchange)",*packet);
            break;
        case 16:
            printf("TXT (%x) (Text Strings)",*packet);
            break;
        case 28:
            printf("AAAA (%x) (IPv6 Address)",*packet);
            break;
        case 251:
            printf("IXFR (%x) (Incremental Zone Transfer)",*packet);
            break;
        case 252:
            printf("AXFR (%x) (Zone Transfer)",*packet);
            break;
        default:
            printf("Unknown");
            break;
    }
    printf("\n");
    return ;
}

void print_classv2(uint16_t class){
    switch(class){
        case 1:
            printf("IN");
            break;
        case 2:
            printf("CS");
            break;
        case 3:
            printf("CH");
            break;
        case 4:
            printf("HS");
            break;
        default:
            printf("Unknown");
            break;
    }
    return ;
}

void print_typev2(uint16_t type){
    switch(type){
        case 1:
            printf("A, ");
            break;
        case 2:
            printf("NS, ");
            break;
        case 3:
            printf("MD, ");
            break;
        case 4:
            printf("MF, ");
            break;
        case 5:
            printf("CNAME, ");
            break;
        case 6:
            printf("SOA, ");
            break;
        case 12:
            printf("PTR, ");
            break;
        case 13:
            printf("HINFO, ");
            break;
        case 14:
            printf("MINFO, ");
            break;
        case 15:
            printf("MX, ");
            break;
        case 16:
            printf("TXT, ");
            break;
        case 28:
            printf("AAAA, ");
            break;
        case 251:
            printf("IXFR, ");
            break;
        case 252:
            printf("AXFR, ");
            break;
        default:
            printf("Unknown, ");
            break;
    }
    return ;
}
        

int getQR(unsigned char byte){
    return byte >> 7;
}


void dns_print_answers(const unsigned char *packet, int verbose,char* name){
    //I use packet_v3 to not modify the packet pointer and to treat the verbose level 3
    const unsigned char *packet_v3=packet;
    printf("type ");
    packet++;
    packet_v3++;
    print_typev2(*packet);
    printf("class ");
    packet+=2;
    print_classv2(*packet);
    printf(", ");
    packet+=5;
    int length=packet[0]*256 + packet[1];
    packet+=2;
    print_answer(packet,*packet_v3,length);

}


void dns_print_queries(const unsigned char *packet, int verbose,bool answer){
    //I use packet_v3 to not modify the packet pointer and to treat the verbose level 3
    const unsigned char *packet_v3=packet;
    //create a buffer to store the name
    char* name;

    if(verbose>=2){
        name=malloc(256);
        printf("    "); 
        int i=0;
        if(!answer){
            free(name);
        }
        printf("    ");
        while(*packet!=0x00){
            if(isprint(*packet)){
                printf("%c",*packet);
                if(answer){
                    name[i]=*packet;
                    i++;
                }
            }
            else{
                printf(".");
                if(answer){
                    name[i]='.';
                    i++;
                }
            }
            packet++;
        }
        printf(": type ");
        print_typev2(packet[1]*256 + packet[2]);
        printf("class ");
        print_classv2(packet[3]*256 + packet[4]);
        printf("\n");
        packet++;

        if(verbose==3){
            printf("        Name: ");
            int length=0;
            int label=1;
            while(*packet_v3!=0x00){
                if(isprint(*packet_v3)){
                    printf("%c",*packet_v3);
                }
                else{
                    printf(".");
                    label++;
                }
                length++;
                packet_v3++;
            }
            packet_v3++;
            printf("\n");
            printf("        [Name Length: %d]\n", length);
            printf("        [Label Count: %d]\n", label);
            printf("        Type: ");
            packet_v3++;
            print_typev3(packet_v3,*packet_v3);
            printf("        Class: ");
            packet_v3+=2;
            print_classv3(*packet_v3);
            packet_v3++;
        }
    }
    packet+=4;
    if(*packet==0xc0 && *(packet+1)==0x0c && answer==true){
        packet+=2;
        printf("    Answers\n");
        printf("        %s: ", name);
        dns_print_answers(packet, verbose, name);
    }

}

void dns_print(const unsigned char *packet, int verbose,int MSB, bool answer){
    printf("    Transaction ID: 0x%02x%02x\n", packet[0], packet[1]);
    printf("    Flags: 0x%02x%02x", packet[2], packet[3]);
    int flags=packet[2]*256 + packet[3];
    if(flags & 0x81){
        printf(" Standard query response, No error\n");
    }
    else{
        printf(" Standard query\n");
    }
                
    if(verbose>2){
        printf("        %d... .... .... .... = Response: Message is a ", getQR(packet[2]));
        if(getQR(packet[2])==0){
            printf("query:\n");
        }
        else{
            printf("response:\n");
        }
        printf("        .%d.. .... .... .... = Opcode: ", (packet[2] >> 3) & 0x1);
        switch((packet[2] >> 3) & 0x1){
            case 0:
                printf("standard query (0)\n");
                break;
            case 1:
                printf("inverse query (1)\n");
                break;
            case 2:
                printf("server status request (2)\n");
                break;
            case 3:
                printf("reserved (3)\n");
                break;
            case 4:
                printf("notify (4)\n");
                break;
            case 5:
                printf("update (5)\n");
                break;

            default:
                printf("Unknown\n");
                break;
        }
        if(MSB==1){
            printf("        ..%d. .... .... .... = Authoritative: ", (packet[2] >> 2) & 0x1);
            if((packet[2] >> 2) & (0x1==0)){
                printf("server is not an authority for domain\n");
                }
            else{
                printf("server is an authority for domain\n");
            }
        }
        printf("        ...%d .... .... .... = Truncated: ", (packet[2] >> 1) & 0x1);
        if((packet[2] >> 1) & (0x1==0)){
            printf("message is not truncated\n");
        }
        else{
            printf("message is truncated\n");
        }
        printf("        .... %d... .... .... = Recursion desired: ", packet[2] & 0x1);
        if(packet[2] & (0x1==0)){
            printf("do not query recursively\n");
        }
        else{
            printf("do query recursively\n");
        }
        printf("        .... .%d.. .... .... = Recursion available: ", packet[3] >> 7);
        if(packet[3] >> 7==0){
            printf("server can not query recursively\n");
        }
        else{
            printf("server can query recursively\n");
        }
        printf("        .... ..%d. .... .... = Z: reserved (0)\n", (packet[3] >> 6) & 0x1);
        if(MSB==1){
            printf("        .... ...%d .... .... = Answer authenticated: ", (packet[3] >> 5) & 0x1);
            if((packet[3] >> 5) & (0x1==0)){
                printf("answer/authority portion was not authenticated by the server\n");
            }
            else{
                printf("answer/authority portion was authenticated by the server\n");
            }
        }
        printf("        .... .... %d... .... = Non-authenticated data: ", (packet[3] >> 4) & 0x1);
        if((packet[3] >> 4) & (0x1==0)){
            printf("unacceptable\n");
        }
        else{
            printf("acceptable\n");
        }
        if(MSB==1){
            printf("        .... .... .%d.. .... = Reply code: ", packet[3] & 0xF); 
            switch(packet[3] & 0xF){
                case 0:
                    printf("No error (0)\n");
                    break;
                case 1:
                    printf("Format error (1)\n");
                    break;
                case 2:
                    printf("Server failure (2)\n");
                    break;
                case 3:
                    printf("Name Error (3)\n");
                    break;
                case 4:
                    printf("Not Implemented (4)\n");
                    break;
                case 5:
                    printf("Refused (5)\n");
                    break;
                case 6:
                    printf("YXDomain (6)\n");
                    break;
                case 7:
                    printf("YXRRSet (7)\n");
                    break;
                case 8:
                    printf("NXRRSet (8)\n");
                    break;
                case 9:
                    printf("NotAuth (9)\n");
                    break;
                case 10:
                    printf("NotZone (10)\n");
                    break;
                case 11:
                    printf("DSOTYPENI (11)\n");
                    break;
                case 12:
                    printf("Reserved (12)\n");
                    break;
                case 13:
                    printf("Reserved (13)\n");
                    break;
                case 14:
                    printf("Reserved (14)\n");
                    break;
                case 15:
                    printf("Reserved (15)\n");
                    break;
                default:
                    printf("Unknown\n");
                    break;
            }
        }
    }
    printf("    Questions: %d\n", packet[4]*256 + packet[5]);
    printf("    Answer RRs: %d\n", packet[6]*256 + packet[7]);
    printf("    Authority RRs: %d\n", packet[8]*256 + packet[9]);
    printf("    Additional RRs: %d\n", packet[10]*256 + packet[11]);
    

    printf("    Queries\n");
    packet+=13;
    //I put packet in the first byte of the first query to simplify the code
    //Before I don't do that to avoid to modify the packet pointer and to underline the constant length of the header
    //I add 13 not 12 to ignore the first byte of the first query 
    
    dns_print_queries(packet, verbose, answer);
    

    return ;
}

void dns(const unsigned char *packet, int verbose,int type, uint16_t* option_length,int protocol){
    printf("Domain Name System");
    const unsigned char * dns_packet;
    switch(type){
        case 4:
            switch(protocol){
                case 0:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + *option_length;
                    break;

                case 1:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
                    break;
                
                default:
                    printf("Unknown\n");
                    break;
            }
            bool answ=false;
            int MSB=getQR(dns_packet[2]);
            if(MSB==0){
                printf(" (query)\n");
            }
            else{
                printf(" (response)\n");
                answ=true;
            }

            if(verbose>1){
                dns_print(dns_packet, verbose, MSB, answ);
            }

            break;
        case 6:
            switch(protocol){
                case 0:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + *option_length;
                    break;

                case 1:
                    dns_packet=packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
                    break;
                
                default:
                    printf("Unknown\n");
                    break;
            }
            bool answer=false;
            MSB=getQR(dns_packet[2]);
            if(MSB==0){
                printf(" (query)\n");
            }
            else{
                printf(" (response)\n");
                answer=true;
            }

            if(verbose>1){
                dns_print(dns_packet, verbose, MSB, answer);
            }
            break;
        default:
            printf("Unknown\n");
            break;
    }
}