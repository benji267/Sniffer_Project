#include "dns.h"

//Every working but there's some problems with the label i the answer section.
//I don't completely print the name of the name server.
//Finally I don't have the Authority section.


//This function is used to print the label of the DNS packet.
//I go back to the beginning of the packet and go to the offset, th next byte is the length of the label.
//I print the label and I go to the next label.
void return_label(const unsigned char* packet,int label_position){
    int length=packet[label_position];
    for(int i=0;i<length;i++){
        if(isprint(packet[label_position+i+1])){
            printf("%c",packet[label_position+i+1]);
        }
        else{
            printf(".");
        }
    }
    return ;
}


//This function is used to print the answer section of the DNS packet with the payload.
void print_answer(const unsigned char* initial_packet,const unsigned char* packet,uint16_t type,int data_length,bool specialisation){
    switch(type){
        case 1:
            if(!specialisation){
                printf("addr ");
            }
            for(int i=0;i<data_length;i++){
                printf("%u",packet[i]);
                if(i!=data_length-1){
                    printf(".");
                }
            }
            printf("\n");
            break;
        case 2:
            if(!specialisation){
                printf  ("name server");
            }
            for(
                int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                }
            }
            printf("\n");
            break;
        case 3:
            if(!specialisation){
                printf("mail destination ");
            }
            for(int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 4:
            if(!specialisation){
                printf("mail forwarder ");
            }
            for(int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 5:
            if(!specialisation){
                printf("cname ");
            }
            packet++;
            for(int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 6:
            if(!specialisation){
                printf("primary name server ");
            }
            for(int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 12:
            if(!specialisation){
                printf("ptr ");
            }
            for(int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 15:
            if(!specialisation){
                printf("mail exchange ");
            }
            for(int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 16:
            if(!specialisation){
                printf("txt ");
            }
            for(int i=0;i<data_length-1;i++){
                if(isprint(packet[i])){
                    printf("%c",packet[i]);
                }
                else{
                    printf(".");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;

        case 28:
            if(!specialisation){
                printf("addr ");
            }
            for(int i=0;i<data_length;i++){
                printf("%x",packet[i]);
                if(i!=data_length-1){
                    printf(":");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 251:
            if(!specialisation){
                printf("ixfr ");
            }
            for(int i=0;i<data_length-1;i++){
                printf("%x",packet[i]);
                if(i!=data_length-1){
                    printf(":");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
                }
            }
            printf("\n");
            break;
        case 252:
            if(!specialisation){
                printf("axfr ");
            }
            for(int i=0;i<data_length-1;i++){
                printf("%x",packet[i]);
                if(i!=data_length-1){
                    printf(":");
                }
                if(packet[i]==0xc0){
                    return_label(initial_packet,packet[i+1]);
                    break;
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

//This function is used to print the class of the DNS packet for the verbose level 3.
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


//This function is used to print the type of the DNS packet for the verbose level 3.
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


//This function is used to print the class of the DNS packet for the verbose level 2.
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

//This function is used to print the type of the DNS packet for the verbose level 2.
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
        
//This function is used to get the MSB of the first byte of the DNS packet.
int getQR(unsigned char byte){
    return byte >> 7;
}

//This function is used to print the answer section of the DNS packet for the verbose level 3.
void print_answerv3(uint16_t type){
    switch(type){
        case 1:
            printf("Adress: ");
            break;
        case 2:
            printf("Name server: ");
            break;
        case 3:
            printf("Mail destination: ");
            break;
        case 4:
            printf("Mail forwarder: ");
            break;
        case 5:
            printf("CNAME: ");
            break;
        case 6:
            printf("Primary name server: ");
            break;
        case 12:
            printf("PTR: ");
            break;
        case 15:
            printf("Mail exchange: ");
            break;
        case 16:
            printf("TXT: ");
            break;
        case 28:
            printf("Adress: ");
            break;
        case 251:
            printf("IXFR: ");
            break;
        case 252:
            printf("AXFR: ");
            break;
        default:
            printf("Unknown: ");
            break;
    }
    return ;
}
        



void dns_print_answers(const unsigned char* initial_packet,const unsigned char *packet, int verbose,char* name){
    //I use packet_v3 to not modify the packet pointer and to treat the verbose level 3
    const unsigned char *packet_v3=packet;
    printf("type ");
    packet++;
    packet_v3++;
    //I need to print the type and class of the answer for the verbose level 2 and 3.
    print_typev2(*packet);
    printf("class ");
    packet+=2;
    print_classv2(*packet);
    printf(", ");
    packet+=5;
    int length=packet[0]*256 + packet[1];
    packet+=2;
    print_answer(initial_packet,packet,*packet_v3,length,false);
    packet+=length;
    if(verbose==3){
        //Special Display for the verbose level 3.
        printf("         |- Name: %s\n", name);
        uint16_t type=*packet_v3;
        printf("         |- Type: ");
        print_typev3(packet_v3,*packet_v3);
        printf("         |- Class: ");
        packet_v3+=2;
        print_classv3(*packet_v3);
        packet_v3++;
        int ttl=packet_v3[0]*16777216 + packet_v3[1]*65536 + packet_v3[2]*256 + packet_v3[3];
        printf("         |- Time to live: %d", ttl);
        if(ttl>60){
            int minutes=ttl/60;
            int seconds=ttl%60;
            printf(" (%d minutes, %d seconds)\n", minutes, seconds);
        }
        else{
            printf(" (%d seconds)\n", ttl);
        }
        packet_v3+=4;
        int data_length=packet_v3[0]*256 + packet_v3[1];
        printf("         |- Data length: %d\n", data_length);
        packet_v3+=2;
        printf("         |- ");
        print_answerv3(type);
        print_answer(initial_packet,packet_v3,type,data_length,true);
    }

    //Now I start a loop for each answer to finish the answer section
    while(1){
        //If the first byte of the answer is 0xc0, it means that I need to go to the label.
        //Moreover that means that it's a name server following this label.
        if(*packet==0xc0){
            printf("\n");
            printf("     |- ");
            return_label(initial_packet,packet[1]);
            printf(": ");
            packet+=2;
            dns_print_answers(initial_packet,packet, verbose, name);
        }
        //I find the end of the answer section.
        else{
            break;
        }
    }
    return ;
}


void dns_print_queries(const unsigned char* initial_packet,const unsigned char *packet, int verbose,bool answer){
    //I use packet_v3 to not modify the packet pointer and to treat the verbose level 3
    const unsigned char *packet_v3=packet;
    //create a buffer to store the name for the possible answer section.
    char* name;

    if(verbose>=2){
        name=malloc(256);
        int i=0;
        //I use a boolean to know if I need to free the name buffer or not.
        if(!answer){
            free(name);
        }
        printf("     |- ");
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
            printf("         |- Name: ");
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
            printf("         |- [Name Length: %d]\n", length);
            printf("         |- [Label Count: %d]\n", label);
            printf("         |- Type: ");
            packet_v3++;
            print_typev3(packet_v3,*packet_v3);
            printf("         |- Class: ");
            packet_v3+=2;
            print_classv3(*packet_v3);
            packet_v3++;
        }
    }
    packet+=4;
    //If the packet is a response, I need to ignore the name and the type and class fields.
    if(*packet==0xc0 && *(packet+1)==0x0c && answer==true){
        packet+=2;
        printf(" |- Answers\n");
        printf("     |- %s: ", name);
        dns_print_answers(initial_packet,packet, verbose, name);
    }

}

void dns_print(const unsigned char *packet, int verbose,int MSB, bool answer){
    //Get the same Display as Wireshark.

    //Need the original packet to go to the the right label.
    const unsigned char *initial_packet=packet;
    printf(" |- Transaction ID: 0x%02x%02x\n", packet[0], packet[1]);
    printf(" |- Flags: 0x%02x%02x", packet[2], packet[3]);
    int flags=packet[2]*256 + packet[3];
    if(flags & 0x81){
        printf(" Standard query response, No error\n");
    }
    else{
        printf(" Standard query\n");
    }
                
    if(verbose>2){
        printf("         |- %d... .... .... .... = Response: Message is a ", getQR(packet[2]));
        if(getQR(packet[2])==0){
            printf("query:\n");
        }
        else{
            printf("response:\n");
        }
        printf("         |- .%d.. .... .... .... = Opcode: ", (packet[2] >> 3) & 0x1);
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
            printf("         |- ..%d. .... .... .... = Authoritative: ", (packet[2] >> 2) & 0x1);
            if((packet[2] >> 2) & (0x1==0)){
                printf("server is not an authority for domain\n");
                }
            else{
                printf("server is an authority for domain\n");
            }
        }
        printf("         |- ...%d .... .... .... = Truncated: ", (packet[2] >> 1) & 0x1);
        if((packet[2] >> 1) & (0x1==0)){
            printf("message is not truncated\n");
        }
        else{
            printf("message is truncated\n");
        }
        printf("         |- .... %d... .... .... = Recursion desired: ", packet[2] & 0x1);
        if(packet[2] & (0x1==0)){
            printf("do not query recursively\n");
        }
        else{
            printf("do query recursively\n");
        }
        printf("         |- .... .%d.. .... .... = Recursion available: ", packet[3] >> 7);
        if(packet[3] >> 7==0){
            printf("server can not query recursively\n");
        }
        else{
            printf("server can query recursively\n");
        }
        printf("         |- .... ..%d. .... .... = Z: reserved (0)\n", (packet[3] >> 6) & 0x1);
        if(MSB==1){
            printf("         |- .... ...%d .... .... = Answer authenticated: ", (packet[3] >> 5) & 0x1);
            if((packet[3] >> 5) & (0x1==0)){
                printf("answer/authority portion was not authenticated by the server\n");
            }
            else{
                printf("answer/authority portion was authenticated by the server\n");
            }
        }
        printf("         |- .... .... %d... .... = Non-authenticated data: ", (packet[3] >> 4) & 0x1);
        if((packet[3] >> 4) & (0x1==0)){
            printf("unacceptable\n");
        }
        else{
            printf("acceptable\n");
        }
        if(MSB==1){
            printf("         |- .... .... .%d.. .... = Reply code: ", packet[3] & 0xF); 
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
    printf(" |- Questions: %d\n", packet[4]*256 + packet[5]);
    printf(" |- Answer RRs: %d\n", packet[6]*256 + packet[7]);
    printf(" |- Authority RRs: %d\n", packet[8]*256 + packet[9]);
    printf(" |- Additional RRs: %d\n", packet[10]*256 + packet[11]);
    

    printf(" |- Queries\n");
    packet+=13;
    //I put packet in the first byte of the first query to simplify the code
    //Before I don't do that to avoid to modify the packet pointer and to underline the constant length of the header
    //I add 13 not 12 to ignore the first byte of the first query 
    
    dns_print_queries(initial_packet,packet, verbose, answer);
    

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
            //Need to know if it's a query or a response with the MSB of the first byte of the dns packet.
            //Need this boolean to know if I need to print the answer section or not.
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
    printf("\n");
    return ;
}