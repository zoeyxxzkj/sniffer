/*
 * @Author: your name
 * @Date: 2020-03-24 15:41:19
 * @LastEditTime: 2020-03-24 18:28:47
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /mysniff/protocal.h
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H
#include<iostream>
#include<vector>

//链路层数据包格式
typedef struct _ethheader
{
    u_char DestMac[6];
    u_char SrcMac[6];
    u_short Etype; //
}ETHHEADER;

#define PROTO_IP 0x0800
#define PROTO_ARP 0x0806
#define PROTO_RARP 0x0835


#define IP_RF 0x8000        //reservedfragment flag
#define IP_DF 0x4000        //don't fragment flag
#define IP_MF 0x2000        //more fragment flag
#define IP_OFFMASK 0x1fff   //mask for fragment offset bits

//IP层数据包格式
typedef struct _ipheader
{
    u_char header_len:4;
    u_char version:4;
    u_char tos:8;
    u_short total_len:16;
    u_short ident:16;
    u_short flags:16;
    u_char ttl:8;
    u_char proto:8;
    u_short checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}IPHEADER;

#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_TCP 6
#define PROTO_UDP 17

//IP_OPTION,只定义了4位处理IGMP的处理部分
typedef struct _ip_option
{
    u_char routing_alert[2];
    u_short value;
}IP_OPTION;

//ICMP数据包格式
typedef struct _icmpheader
{
    u_char icmp_type;
    u_char icmp_code;
    u_short icmp_checksum:16;
    u_short icmp_identifier;
    u_short icmp_seqnum;
}ICMPHEADER;

//IGMP数据包格式
typedef struct _igmpheader
{
    u_char igmp_type;
    u_char igmp_max_response_time;
    u_short igmp_checksum:16;
    u_char igmp_group_address[4];
}IGMPHEADER;

//APR数据包格式
typedef struct _arpheader
{
    u_short arp_hrd;
    u_short arp_pro;
    u_char arp_hlen;
    u_char arp_plen;
    u_short arp_op;
    u_char arp_shd[6];
    u_char arp_sip[4];
    u_char arp_dhd[6];
    u_char arp_dip[6];
}ARPHEADER;

//UDP数据包格式
typedef struct _udpheader
{
    u_short udp_src_port:16;
    u_short udp_tar_port:16;
    u_short udp_len:16;
    u_short udp_checksum:16;
}UDPHEADER;

#define TH_FIN 0X01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0X80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

//TCP数据包格式
typedef struct _tcpheader
{
    u_short tcp_src_port:16;
    u_short tcp_des_port:16;
    u_int tcp_seq_num:32;
    u_int tcp_ack:32;
    u_char tcp_resv:4;
    u_char tcp_header_len:4;
    u_char tcp_code_bits;
    u_short tcp_window_size:16;
    u_short tcp_checksum:16;
    u_short tcp_urgent_pointer:16;
}TCPHEADER;

//对包进行计数
typedef struct _pktcount
{
    int n_ip;
    int n_rarp;
    int n_arp;
    int n_tcp;
    int n_udp;
    int n_icmp;
    int n_igmp;
    int n_http;
    int n_other;
    int n_sum;
}PKTCOUNT;

//要保存的数据结构
typedef struct _datapkt
{
    char pktType[8];
    int time[6];
    int len;

    struct _ethheader *eth_header;
    struct _arpheader *arp_header;
    struct _ipheader *ip_header;
    struct _ip_option *ip_option;
    struct _icmpheader *icmp_header;
    struct _igmpheader *igmp_header;
    struct _udpheader *udp_header;
    struct _tcpheader *tcp_header;
    u_char* app_header;
    volatile bool isHttp = false;
    int httpsize;
}DATAPKT;

typedef std::vector<DATAPKT *> datapktVec;
typedef std::vector<u_char *> dataVec;


#endif // PROTOCOL_H
