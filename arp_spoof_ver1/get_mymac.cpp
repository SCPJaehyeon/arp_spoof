#include "header.h"

u_char *get_mymac(char *dev){
    struct ifreq ifr;
    int s;
    if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
        perror("socket");
    }
    strcpy(ifr.ifr_name, dev);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
    }
    u_char *my_mac = (u_char *)ifr.ifr_hwaddr.sa_data;
    return my_mac;
}
