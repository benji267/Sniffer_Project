#include "sniffer.h"


//This function is used to print the information of the fake frame for the case
//we don't have any option (-v or -i).
void example_packet(const unsigned char* packet,int verbose){
    ethernet(packet, verbose);
    ip(packet, verbose);
    uint16_t options_length=0;
    tcp(packet, verbose,4,&options_length);
    verbose+=3;
    http(packet, verbose,4,&options_length);
    return;
}


int main(int argc, char* argv[]){

    if(argc >5 || argc < 2){
        printf("Nombres d'arguments incorrects\n");
        return(1);
    }

    char *interface = NULL;
    char *offlineFile=NULL;
    //char *filter=NULL;
    int verbosity;

    //Parsing the arguments
    for(int i=1; i<argc; i++){
        if(strcmp(argv[i],"-i")==0){
            interface = argv[i+1];
        }
        if(strcmp(argv[i],"-o")==0){
            offlineFile = argv[i+1];
        }
        /*if(strcmp(argv[i],"-f")==0){
            filter = argv[i+1];
        }*/
        if(strcmp(argv[i],"-v")==0){
            verbosity = atoi(argv[i+1]);
        }
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const unsigned char *packet;

    //If we have an interface, we open it.
    if(interface!=NULL){
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL) {
        fprintf(stderr,"Couldn't open interface %s: %s\n", interface, errbuf);
        return -1;
        }
    }
    //If we have a file, we open it.
    else if(offlineFile!=NULL){
        handle = pcap_open_offline(offlineFile, errbuf);

        if (handle == NULL) {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", offlineFile, errbuf);
        return -1;
    }
    }
    else{
        //If we don't have any option (-v or -i), we analyze a special packet.
        example_packet(fakeFrame,verbosity);
        return 0;
    }


    //Principal loop to analyze the packets.
    //I construct it as a switch case to be able to add new protocols easily.
    //I take the choice to parse each packets independently in each protocol function.
    //I think it's better to do that because I can have access to all the information of the packet in the main
    //whatever the protocol is to check if a problem is detected.
    //The only problem could be in DNS because it could be preceded by a TCP or UDP packet.
    //But I add a parameter to the function to know if it's preceded by a TCP or UDP packet (protocol 0 or 1).
    while((packet = pcap_next(handle, &header))){
       
        switch(ethernet(packet, verbosity)){
            int following_protocol;
           case ETHERTYPE_IPV4_Custom:
                following_protocol = ip(packet, verbosity);
                switch(following_protocol){
                    case IPPROTO_ICMP:
                        icmp(packet, verbosity,4);
                        break;
                    case IPPROTO_UDP:
                        int app;
                        app=udp(packet, verbosity,4);
                        switch(app){
                            case DNS:
                                dns(packet,verbosity,4,0,1);
                                break;
                            case BOOTP:
                                bootp(packet,verbosity,4);
                                break;
                            case DHCP:
                                bootp(packet,verbosity,4);
                                break;
                        }
                        break;
                    case IPPROTO_TCP:
                        int application;
                        uint16_t options_length=0;
                        application=tcp(packet, verbosity,4,&options_length);
                        switch(application){
                            case TELNET:
                                telnet(packet, verbosity,4,&options_length);
                                break;
                            case HTTP:
                                http(packet, verbosity,4,&options_length);
                                break;

                            case POP3:
                                pop3(packet, verbosity,4,&options_length);
                                break;
                            case DNS:
                                dns(packet,verbosity,4,&options_length,0);
                                break;
                            case SMTP:
                                smtp(packet,verbosity,4,&options_length);
                                break;
                            case FTP:
                                ftp(packet,verbosity,4,&options_length);
                                break;
                            default:
                                break;
                        }
                        break;
                    case IPPROTO_SCTP:
                        sctp(packet, verbosity,4);
                        break;
                    default:
                        break;
                }
                break;
            case ETHERTYPE_IPV6_Custom:
                following_protocol=ip(packet, verbosity);
                switch(following_protocol){
                    case IPPROTO_ICMPV6:
                        icmp(packet, verbosity,6);
                        break;
                    case IPPROTO_UDP:
                        int app;
                        app=udp(packet, verbosity,6);
                        switch(app){
                            case DNS:
                                dns(packet,verbosity,6,0,1);
                                break;
                            case BOOTP:
                                bootp(packet,verbosity,6);
                                break;
                            case DHCP:
                                bootp(packet,verbosity,6);
                                break;
                        }
                        break;
                    case IPPROTO_TCP:
                        int application;
                        uint16_t options_length=0;
                        application=tcp(packet, verbosity,6,&options_length);
                        switch(application){
                            case TELNET:
                                telnet(packet, verbosity,6,&options_length);
                                break;
                            case HTTP:
                                http(packet, verbosity,6,&options_length);
                                break;

                            case POP3:
                                pop3(packet, verbosity,6,&options_length);
                                break;
                            case DNS:
                                dns(packet,verbosity,6,&options_length,0);
                                break;
                            case SMTP:
                                smtp(packet,verbosity,6,&options_length);
                                break;
                            case FTP:
                                ftp(packet,verbosity,6,&options_length);
                                break;
                            default:
                                break;
                        }
                        break;
                    case IPPROTO_SCTP:
                        sctp(packet, verbosity,6);
                        break;
                    default:
                        break;
                }
                break;
           case ETHERTYPE_ARP_Custom:
                arp(packet, verbosity);
                break;
           default:
                printf("Unknown\n");
                break;
        }
        //I add this function to separate the different packets.
        separe_trame();
    }
    

    
    pcap_close(handle);
    return 0;

}

