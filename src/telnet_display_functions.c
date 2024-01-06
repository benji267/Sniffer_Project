#include "telnet_display_functions.h"


//I create this files to clean the main file and to have a better view of the code.
//I put all the functions that are used to print the telnet options and commands.
//I want to print the options and commands in the same way that wireshark does so 
//for example if verbosity=2, I will print :  Won't Echo
//If verbosity=3, I will print:
//  Won't Echo
// Command: Won't (252)
//Subcommand: Echo 
//That's why I have a function for verbosity=2 and another one for verbosity=3.
//The new_packet3 is just use to print the subcommand and suboption so that's why
//print_telnet_option is different for verbosity=2 and verbosity=3.


void print_telnet_option(const unsigned char** packet,bool s_end,bool suboption,uint16_t *size_telnet,int version){
    const unsigned char** option=packet;
    if(s_end){
        return;
    }

    switch(**option){
        case 0x00:
            printf(" Binary\n");
            break;

        case 0x01:
            printf(" Echo\n");
            break;

        case 0x02:
            printf(" Reconnection\n");
            break;

        case 0x03:
            printf(" Suppress Go Ahead\n");
            break;

        case 0x04:
            printf(" Approx Message Size Negotiation\n");
            break;

        case 0x05:
            printf(" Status\n");
            break;

        case 0x06:
            printf(" Timing Mark\n");
            break;

        case 0x07:
            printf(" Remote Controlled\n");
            break;

        case 0x08:
            printf(" Output Line Width\n");
            break;

        case 0x09:
            printf(" Output Page Size\n");
            break;

        case 0x0a:
            printf(" Output Carriage-Return Disposition\n");
            break;

        case 0x0b:
            printf(" Output Horizontal Tab Stops\n");
            break;

        case 0x0c:
            printf(" Output Horizontal Tab Disposition\n");
            break;

        case 0x0d:
            printf(" Output Formfeed Disposition\n");
            break;

        case 0x0e:
            printf(" Output Vertical Tabstops\n");
            break;

        case 0x0f:
            printf(" Output Vertical Tab Disposition\n");
            break;

        case 0x10:
            printf(" Output Linefeed Disposition\n");
            break;

        case 0x11:
            printf(" Extended ASCII\n");
            break;

        case 0x12:
            printf(" Logout\n");
            break;

        case 0x13:
            printf(" Byte Macro\n");
            break;

        case 0x14:
            printf(" Data Entry Terminal\n");
            break;

        case 0x15:
            printf(" SUPDUP\n");
            break;

        case 0x16:
            printf(" SUPDUP Output\n");
            break;

        case 0x17:
            printf(" Send Location\n");
            break;

        case 0x18:
            printf(" Terminal Type\n");
            break;

        case 0x19:
            printf(" End of Record\n");
            break;

        case 0x1a:
            printf(" TACACS User Identification\n");
            break;

        case 0x1b:
            printf(" Output Marking\n");
            break;

        case 0x1c:
            printf(" Terminal Location Number\n");
            break;

        case 0x1d:
            printf(" Telnet 3270 Regime\n");
            break;

        case 0x1e:
            printf(" X.3 PAD\n");
            break;

        case 0x1f:
            printf(" Negotiate About Window Size\n");
            break;

        case 0x20:
            printf(" Terminal Speed\n");
            break;

        case 0x21:
            printf(" Remote Flow Control\n");
            break;

        case 0x22:
            printf(" Linemode\n");
            break;

        case 0x23:
            printf(" X Display Location\n");
            break;

        case 0x24:
            printf(" Environment Option\n");
            break;

        case 0x25:
            printf(" Authentication Option\n");
            break;

        case 0x26:
            printf(" Encryption Option\n");
            break;

        case 0x27:
            printf(" New Environment Option\n");
            break;

        case 0x28:
            printf(" TN3270E\n");
            break;

        case 0x29:
            printf(" X Auth\n");
            break;

        case 0x2a:
            printf(" Charset\n");
            break;

        case 0x2b:
            printf(" Telnet Remote Serial Port\n");
            break;

        case 0x2c:
            printf(" Com Port Control Option\n");
            break;

        case 0x2d:
            printf(" Telnet Suppress Local Echo\n");
            break;

        case 0x2e:
            printf(" Telnet Start TLS\n");
            break;

        case 0x2f:
            printf(" Kermit\n");
            break;

        case 0x30:
            printf(" Send-URL\n");
            break;

        case 0x31:
            printf(" Forward X\n");
            break;

        case 0x8a:
            printf(" Telopt-Pragma-Logon\n");
            break;

        case 0x8b:
            printf(" Telopt-SSPI-Logon\n");
            break;


        case 0x8c:
            printf(" Telnet-PRAGMA-HEARTBEAT\n");
            break;

    
        case 0xff:
            printf(" Extended-Options-List\n");
            break;

    default:
            printf(" Unknown\n");
            break;

        
    }
    (*option)++;

    if(version==2){
        (*size_telnet)--;
    }

    if(suboption){
        while(**option != IAC){
            (*option)++;
            if(version==2){
                (*size_telnet)--;
            }
        }
        (*option)++;
        if(version==2){
            printf(" |- IAC: ");
            (*size_telnet)--;
        }
        if(version==2){
            print_telnet_commandv2(option,size_telnet);
        }
        else{
            print_telnet_commandv3(option);
        }
    }

    return;
}



void print_telnet_commandv2(const unsigned char** packet,uint16_t *size_telnet){
    const unsigned char** command=packet;
    //boolean to know if the command is the last one and to stop the recursion
    bool s_end=false;
    bool suboption=false;
    //if suboption is true after this function, I continue to advance in the packet until the Suboption End marker.
    //I make this to differentiate between the command/option and the plain text.
    switch(**command){
        case SE:
            printf("Suboption End\n");
            s_end=true;
            break;
            
        case NOP:    
            printf("Nop");
            break;
        
        case DM:    
            printf("Dm");
            break;
        
        case BRK:    
            printf("Brk");
            break;
        
        case IP:    
            printf("Ip");
            break;
        
        case AO:    
            printf("Ao");
            break;
        
        case AYT:       
            printf("Ayt");
            break;
        
        case EC:        
            printf("Ec");
            break;
        
        case EL:    
            printf("El");
            break;
        
        case GA:    
            printf("Ga");
            break;
        
        case SB:    
            printf("Suboption");
            suboption=true;
            break;
        
        case WILL:     
            printf("Will");
            break;
        
        case WONT:    
            printf("Won't");
            break;
        
        case DO:        
            printf("Do");
            break;
        
        case DONT:    
            printf("Don't");
            break;
        
        default:

            printf("Unknown");
            break;
            
    }
    (*command)++;
    (*size_telnet)--;
    print_telnet_option(command,s_end,suboption,size_telnet,2);
    return;
}


//I have to create another function for verbosity=3 because I want to print the command and the option like in wireshark.
void print_telnet_commandv3(const unsigned char** packet){
    const unsigned char** command=packet;
    //boolean to know if the command is the last one and to stop the recursion
    bool s_end=false;
    bool suboption=false;
    printf("     |- Command: ");
    switch(**command){
        case SE:
            printf("Suboption End (240)\n");
            s_end=true;
            break;
        case NOP:    
            printf("Nop (241)");
            break;
        
        case DM:    
            printf("Dm (242)");
            break;
        
        case BRK:    
            printf("Brk (243)");
            break;
        
        case IP:    
            printf("Ip (244)");
            break;
        
        case AO:    
            printf("Ao (245)");
            break;
        
        case AYT:       
            printf("Ayt (246)");
            break;
        
        case EC:        
            printf("Ec (247)");
            break;
        
        case EL:    
            printf("El (248)");
            break;
        
        case GA:    
            printf("Ga (249)");
            break;
        
        case SB:    
            printf("Suboption (250)");
            suboption=true;
            break;
        
        case WILL:     
            printf("Will (251)");
            break;
        
        case WONT:    
            printf("Won't (252)");
            break;
        
        case DO:        
            printf("Do (253)");
            break;
        
        case DONT:    
            printf("Don't (254)");
            break;
        
        default:

            printf("Unknown");
            break;
            
    }
    if(!s_end){
        printf("\n     |- Subcommand:");
    }
    (*command)++;
    print_telnet_option(command,s_end,suboption,NULL,3);
    return;
}

//When we have a suboption, to simplify the code, I print ne number of command and option after the end of the suboption and the print of suboption end.