//[BOB 8TH] JAEHYEON arp_spoof main.cpp CODE
#include "header.h"

static etherh etherh;
static arph arph;
static packet packet;
void Usage(char *argv){
    printf("Usage : %s [Interface] [Sender IP] [Target IP] ... [Sender IP] [Target IP] ...\n", argv);
    printf("Example) ./ARP_Spoof eth0 192.168.0.11 192.168.0.1 ...\n");
}
int main(int argc, char* argv[]){
    if(argc < 4 || argc % 2 != 0){
        Usage(argv[0]);
        return -1;
    }
    printf("argc = %d \n",argc);
    printf("argc-2/2 = %d \n",(argc-2)/2);
    char* dev = argv[1]; //argv[1] = Interface
    /*uint32_t SenIP;
    uint32_t TarIP;
    u_char** sen_mac = (u_char**)malloc(sizeof(u_char*)*((argc-2)/2));
    for(int k=0; k<(argc-2)/2; k++)
    {
        sen_mac[k] = (u_char*)malloc(sizeof(u_char)*6);
    }*/

    u_char* my_mac; //MyMac
    /*int k=0;
    for(int i = 2; i < argc;i += 2){
        SenIP = inet_addr(argv[i]); //argv[2] = Sender IP
        TarIP = inet_addr(argv[i+1]); //argv[3] = Target IP
        my_mac = get_mymac(dev); //Get MyMac
        printf("k : %d \n",k);
        memcpy(sen_mac[k],get_senmac(dev, my_mac, SenIP),6); //Get TarMac
        k += 1;
    }*/
    my_mac = get_mymac(dev); //Get MyMac
    packet_relay(dev, my_mac, argc, argv);
    /*while(true){
        l = 0;
        for(int i = 2; i < argc;i += 2){  
            SenIP = inet_addr(argv[i]); //argv[2] = Sender IP
            TarIP = inet_addr(argv[i+1]); //argv[3] = Target IP
            my_mac = get_mymac(dev); //Get MyMac
            printf("l : %d \n",l);

            //arp_spoof(dev, my_mac, sen_mac[l], SenIP, TarIP); //ARP Spoofs
            l += 1;
        }
        sleep(2);
    }*/
}



