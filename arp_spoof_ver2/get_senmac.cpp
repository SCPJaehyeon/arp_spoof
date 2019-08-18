#include "header.h"

static etherh etherh;
static arph arph;
static packet packet;
u_char* get_senmac(char *dev, u_char *my_mac, uint32_t SenIP){
    u_char broadMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    u_char nothingMac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t MyIP[4] = {172,20,10,4};
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    memcpy(&etherh.DMAC, &broadMac[0], 6); //Destination MAC = BroadCast
    memcpy(&etherh.SMAC, &my_mac[0], 6); //Source MAC = MY
    arph.op = 0x0100; //ARP Request
    memcpy(&arph.SenMAC, &my_mac[0], 6); //Sender MAC = MY
    memcpy(&arph.SenIP, &MyIP[0],4); //Sender IP = MY
    memcpy(&arph.TarMAC, &nothingMac[0], 6); //Target MAC = Nothing
    memcpy(&arph.TarIP, &SenIP, sizeof(SenIP)); //Target IP
    packet.eth = etherh;
    packet.arp = arph;

    int res = pcap_sendpacket(handle,(u_char*)&packet, 42); //send ARP Request Packet
    if(res == -1){
        printf("Send Fail \n");
    }else{
        printf("Send Success \n");
    }
    struct pcap_pkthdr *header;
    const unsigned char *packet_read;
    int res1;

    while(true){
        res1=pcap_next_ex(handle, &header, &packet_read);
        if(res1==1 && packet_read[21]==0x02&& packet_read[13]==0x06){
            u_char* sen_mac = (u_char *)&packet_read[6];
            return sen_mac;
        }else {
            printf("Target MAC Finding.. \n");
        }pcap_close(handle);
    }

}
