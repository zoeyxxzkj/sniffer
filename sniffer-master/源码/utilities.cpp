/*
 * @Author: your name
 * @Date: 2020-03-24 16:26:53
 * @LastEditTime: 2020-03-24 16:26:53
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /mysniff/utilities.cpp
 */
#include "utilities.h"
#include<string.h>
#include <QDebug>

int utilities::analyze_frame(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket)
{
    pktInitialAddress = pkt;
    struct _ethheader *eth_header = (struct _ethheader *)pkt;
    data->eth_header = (struct _ethheader *)malloc(sizeof(struct _ethheader));
    if(data->eth_header == NULL)
    {
        qDebug() << "failed to malloc ethheader space."<<endl;
        return -1;
    }
    for(int i = 0; i < 6; i++)
    {
        data->eth_header->SrcMac[i] = eth_header->SrcMac[i];
        data->eth_header->DestMac[i] = eth_header->DestMac[i];
    }
    npacket->n_sum++;

    data->eth_header->Etype = ntohs(eth_header->Etype);

    int ret = 0;

    switch (data->eth_header->Etype)
    {
        case PROTO_IP:
            //mac_type="IPv4";
            //printf("Type: %s(0x%02X%02X)\n",mac_type.c_str(),eth_header->Etype[0],eth_header->Etype[1]);
            ret = analyze_ip((u_char*)pkt+14, data, npacket);
            break;
        case PROTO_ARP:
            //mac_type="ARP";
            //printf("Type: %s(0x%02X%02X)\n",mac_type.c_str(),eth_header->Etype[0],eth_header->Etype[1]);
            ret = analyze_arp((u_char*)pkt+14, data, npacket, false);
            break;
        case PROTO_RARP:
            //mac_type="RARP";
            //printf("Type: %s(0x%02X%02X)\n",mac_type.c_str(),eth_header->Etype[0],eth_header->Etype[1]);
            ret = analyze_arp((u_char*)pkt+14, data, npacket, true);
            break;
        default:
            //mac_type="Unknown";
            npacket->n_other++;
            ret = -1;
            break;
    }
    return ret;
}

int utilities::analyze_arp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket, bool A_R)
{
    struct _arpheader *arp_header = (struct _arpheader *)pkt;
    data->arp_header = (struct _arpheader *)malloc(sizeof(struct _arpheader));
    if(data->arp_header == NULL)
    {
        qDebug() << "failed to malloc arpheader space." <<endl;
        return -1;
    }

    for(int i = 0; i < 6; i++)
    {
        if(i < 4)
        {
            data->arp_header->arp_sip[i] = arp_header->arp_sip[i];
            data->arp_header->arp_dip[i] = arp_header->arp_dip[i];
        }
        data->arp_header->arp_shd[i] = arp_header->arp_shd[i];
        data->arp_header->arp_dhd[i] = arp_header->arp_dhd[i];
    }
    data->arp_header->arp_hrd = ntohs(arp_header->arp_hrd);
    data->arp_header->arp_pro = ntohs(arp_header->arp_pro);
    data->arp_header->arp_op = ntohs(arp_header->arp_op);
    data->arp_header->arp_plen = arp_header->arp_plen;
    data->arp_header->arp_hlen = arp_header->arp_hlen;

    if(A_R)
    {
        strcpy(data->pktType, "RARP");
        npacket->n_rarp++;
    }
    else
    {
        strcpy(data->pktType, "ARP");
        npacket->n_arp++;
    }
    return 1;
}

int utilities::analyze_ip(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket)
{
    struct _ipheader *ip_header = (struct _ipheader*)pkt;
    data->ip_header = (struct _ipheader*)malloc(sizeof(struct _ipheader));
    if(data->ip_header == NULL)
    {
        qDebug() << "failed to malloc ipheader space." << endl;
        return -1;
    }

    data->ip_header->header_len = ip_header->header_len;
    data->ip_header->version = ip_header->version;
    data->ip_header->tos = ip_header->tos;
    data->ip_header->total_len = ntohs(ip_header->total_len);
    data->ip_header->ident = ntohs(ip_header->ident);
    data->ip_header->flags = ntohs(ip_header->flags);
    data->ip_header->ttl = ip_header->ttl;
    data->ip_header->proto = ip_header->proto;
    data->ip_header->checksum = ntohs(ip_header->checksum);
    npacket->n_ip++;

    for(int i = 0; i < 4; i++)
    {
        data->ip_header->sourceIP[i] = ip_header->sourceIP[i];
        data->ip_header->destIP[i] = ip_header->destIP[i];
    }

    u_short ip_header_len = data->ip_header->header_len*4;
    int ret = 0;

    switch (ip_header->proto)
    {
        case PROTO_ICMP:
        {
            //ip_proto="ICMP";
            //printf("IP protocol : %s (%d)\n",ip_proto.c_str(),ip_header->proto);
            ret = analyze_icmp((u_char*)pkt+ip_header_len, data, npacket);
            break;
        }
        case PROTO_IGMP:
        {
            // ip_proto="IGMP";
            // printf("IP protocol : %s (%d)\n",ip_proto.c_str(),ip_header->proto);
            // IP_OPTION *ip_option=(IP_OPTION*)(pkt_data+14+20);
            // ip_option->value=ntohs(ip_option->value);
            // if(ip_option->value==1)
            //     printf("Options : (%d bytes)\n",(ip_header->header_len-5)*4);
            //     printf("Router alert : Every router examines packet\n");
            // IGMP_handle(header,pkt_data,ip_header->header_len*4);
            ret = analyze_igmp((u_char*)pkt+ip_header_len, data, npacket);
            break;
        }
        case PROTO_TCP:
        {
            // ip_proto="TCP";
            // printf("IP protocol : %s (%d)\n",ip_proto.c_str(),ip_header->proto);
            // TCP_handle(header,pkt_data,ip_header->header_len*4);
            ret = analyze_tcp((u_char*)pkt+ip_header_len, data, npacket);
            break;
        }
        case PROTO_UDP:
         {
            // ip_proto="UDP";
            // printf("IP protocol : %s (%d)\n",ip_proto.c_str(),ip_header->proto);
            // UDP_handle(header,pkt_data,ip_header->header_len*4);
            ret = analyze_udp((u_char*)pkt+ip_header_len, data, npacket);
            break;
         }
        default:
        {
            npacket->n_other++;
            ret = -1;
            break;

        }
    }
    return ret;
}

int utilities::analyze_icmp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket)
{
    struct _icmpheader* icmp_header = (struct _icmpheader*)pkt;
    data->icmp_header = (struct _icmpheader*)malloc(sizeof(struct _icmpheader));

    if(icmp_header == NULL)
    {
       qDebug() << "failed to malloc icmpheader space." << endl;
       return -1;
    }

    data->icmp_header->icmp_type = icmp_header->icmp_type;
    data->icmp_header->icmp_code = icmp_header->icmp_code;
    data->icmp_header->icmp_checksum=ntohs(icmp_header->icmp_checksum);
    data->icmp_header->icmp_identifier=ntohs(icmp_header->icmp_identifier);
    data->icmp_header->icmp_seqnum=ntohs(icmp_header->icmp_seqnum);
    npacket->n_icmp++;
    strcpy(data->pktType, "ICMP");
    return 1;
}

int utilities::analyze_igmp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket)
{
    struct _igmpheader *igmp_header = (struct _igmpheader*)pkt;

    data->igmp_header = (struct _igmpheader*)malloc(sizeof(struct _igmpheader));

    if(igmp_header == NULL)
    {
       qDebug() << "failed to malloc igmpheader space." << endl;
       return -1;
    }

    data->igmp_header->igmp_type = igmp_header->igmp_type;
    data->igmp_header->igmp_max_response_time = igmp_header->igmp_max_response_time;
    data->igmp_header->igmp_checksum=ntohs(igmp_header->igmp_checksum);
    for(int i = 0; i < 4; i++)
    {
        data->igmp_header->igmp_group_address[i] = igmp_header->igmp_group_address[i];
    }
    npacket->n_igmp++;
    strcpy(data->pktType, "IGMP");
    return 1;
}

int utilities::analyze_tcp(const u_char *pkt, DATAPKT *data, PKTCOUNT *npacket)
{
    struct _tcpheader* tcp_header=(struct _tcpheader*)pkt;

    data->tcp_header = (struct _tcpheader*)malloc(sizeof(struct _tcpheader));

    if(tcp_header == NULL)
    {
       qDebug() << "failed to malloc tcpheader space." << endl;
       return -1;
    }

    data->tcp_header->tcp_src_port=ntohs(tcp_header->tcp_src_port);
    data->tcp_header->tcp_des_port=ntohs(tcp_header->tcp_des_port);
    data->tcp_header->tcp_seq_num=ntohl(tcp_header->tcp_seq_num);
    data->tcp_header->tcp_ack=ntohl(tcp_header->tcp_ack);
    data->tcp_header->tcp_resv=tcp_header->tcp_resv;
    data->tcp_header->tcp_code_bits=tcp_header->tcp_code_bits;
    data->tcp_header->tcp_header_len=tcp_header->tcp_header_len;
    data->tcp_header->tcp_window_size=ntohs(tcp_header->tcp_window_size);
    data->tcp_header->tcp_checksum=ntohs(tcp_header->tcp_checksum);
    data->tcp_header->tcp_urgent_pointer=ntohs(tcp_header->tcp_urgent_pointer);
    npacket->n_tcp++;

    if(data->tcp_header->tcp_src_port == 80 || data->tcp_header->tcp_des_port == 80)
    {
        u_char *http_data = (u_char *)tcp_header + data->tcp_header->tcp_header_len * 4;
        const char *token[] = {"GET", "POST", "HTTP/1.1", "HTTP/1.0"};
        u_char *http_header;

        for(int i = 0; i < 4; i++)
        {
            http_header = (u_char *)strstr((char *)http_data,token[i]);
            if(http_header)
            {
                int size = data->len - ((u_char *)http_data - pktInitialAddress);
                if(size == 0)
                {
                    break;
                }
                npacket->n_http++;
                strcpy(data->pktType, "HTTP");
                data->isHttp = true;
                qDebug() << "find a http packet." << endl;

                qDebug() << "size: "+ size << endl;

                data->httpsize = size;
                data->app_header = (u_char *)malloc(size * sizeof(u_char));
                for(int j = 0; j < size; j++)
                {
                    data->app_header[j] = http_data[j];
                }
                return 1;
            }
        }
        strcpy(data->pktType, "TCP");
    }
    strcpy(data->pktType, "TCP");
    return 1;
}

int utilities::analyze_udp(const u_char*pkt, DATAPKT *data, PKTCOUNT *npacket)
{
    struct _udpheader* udp_header = (struct _udpheader*)pkt;

    data->udp_header = (struct _udpheader*)malloc(sizeof(struct _udpheader));

    if(udp_header == NULL)
    {
       printf("failed to malloc udpheader space.\n");
        return -1;
    }

    data->udp_header->udp_src_port=ntohs(udp_header->udp_src_port);
    data->udp_header->udp_tar_port=ntohs(udp_header->udp_tar_port);
    data->udp_header->udp_len=ntohs(udp_header->udp_len);
    data->udp_header->udp_checksum=ntohs(udp_header->udp_checksum);
    npacket->n_udp++;
    strcpy(data->pktType, "UDP");
    return 1;
}
