#ifndef UTILITIES_H
#define UTILITIES_H


#include<pcap.h>
#include"protocol.h"

class utilities
{
public:
    int analyze_frame(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket);
    int analyze_arp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket, bool A_R);
    int analyze_ip(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket);
    int analyze_icmp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket);
    int analyze_igmp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket);
    int analyze_tcp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket);
    int analyze_udp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket);
private:
    const u_char *pktInitialAddress;  //捕获的数据包的起始地址
};


#endif // UTILITIES_H
