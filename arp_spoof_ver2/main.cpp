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
    u_char* my_mac; //MyMac

    my_mac = get_mymac(dev); //Get MyMac
    packet_relay(dev, my_mac, argc, argv);

}



