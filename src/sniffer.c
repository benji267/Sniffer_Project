#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "sctp.h"
#include "telnet.h"


int main(int argc, char* argv[]){

    if(argc >5 || argc < 2){
        printf("Nombres d'arguments incorrects\n");
        return(1);
    }

    //char *interface = NULL;
    char *offlineFile=NULL;
    //char *filter=NULL;
    int verbosity;

    for(int i=1; i<argc; i++){
        /*if(strcmp(argv[i],"-i")==0){
            interface = argv[i+1];
        }*/
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
    handle = pcap_open_offline(offlineFile, errbuf);
    if (handle == NULL) {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", "test.pcap", errbuf);
        return(2);
    }

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
                        udp(packet, verbosity,4);
                        break;
                    case IPPROTO_TCP:
                        int application;
                        uint16_t options_length=0;
                        application=tcp(packet, verbosity,4,&options_length);
                        switch(application){
                            case TELNET:
                                telnet(packet, verbosity,4,&options_length);
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
                        udp(packet, verbosity,6);
                        break;
                    case IPPROTO_TCP:
                        uint16_t options_length=0;
                        tcp(packet, verbosity,6,&options_length);
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
    }
    

    
    pcap_close(handle);
    return 0;

}

