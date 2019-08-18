//[BOB 8TH] JAEHYEON arp_spoof header.h CODE
#pragma once
#ifndef HEADER_H
#define HEADER_H

#define ETYPE 0x0608
#define HTYPE 0x0100
#define PTYPE 0x0008

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdlib.h>



struct etherh { //Ethernet header
    u_char DMAC[6];
    u_char SMAC[6];
    uint16_t Type = ETYPE;
};
struct arph { //ARP header
    uint16_t Htype = HTYPE;
    uint16_t Ptype = PTYPE;
    uint8_t Hlen = 6;
    uint8_t Prolen = 4;
    uint16_t op;
    u_char SenMAC[6];
    uint8_t SenIP[4];
    u_char TarMAC[6];
    uint8_t TarIP[4];
};
struct iph{
    uint8_t verandh;
    uint8_t service;
    uint16_t totallength;
    uint16_t identi;
    uint16_t offset;
    uint8_t ttl;
    uint8_t pro;
    uint16_t checks;
    uint8_t SIP[4];
    uint8_t DIP[4];
};

struct packet {
    struct etherh eth;
    struct arph arp;
};
struct repacket {
    struct etherh eth;
    struct iph iph;
};


u_char*get_mymac(char *dev);
u_char*get_senmac(char *dev, u_char *my_mac, uint32_t SenIP);
u_char*get_tarmac(char *dev, u_char *my_mac, uint32_t TarIP);
int arp_spoof(char *dev, u_char *my_mac,u_char *tar_mac,uint32_t SenIP, uint32_t TarIP);
void packet_relay(char *dev,u_char *my_mac, int argc, char **argv);
#endif // HEADER_H
