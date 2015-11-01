#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include "common.h"
#include "util.hpp"

class PacketHandler {
public:
    /*
    * To handle non-ip and not arp packets
    */
    bool handle_others(u_char *args, const u_char* packet, PCAP_PKTHEADER *pktHeader, pcap_dumper_t *pd, struct ether_header *eptr) {
        if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP) {
            printf("RARP!\n");
        }
        else if (ntohs (eptr->ether_type) == ETHERTYPE_SPRITE){
            printf("SPRITE!\n");
        }
        else if (ntohs (eptr->ether_type) == ETHERTYPE_AT) {
            printf("AT!\n");
        }
        else if (ntohs (eptr->ether_type) == ETHERTYPE_AARP) {
            printf("AARP!\n");
        }
        else if (ntohs (eptr->ether_type) == ETHERTYPE_VLAN) {
            printf("VLAN!\n");
        }
        else if (ntohs (eptr->ether_type) == ETHERTYPE_IPX) {
            printf("IPX!\n");
        }
        else if (ntohs (eptr->ether_type) == ETHERTYPE_IPV6) {
            printf("IPV6!\n");
        }
        else if (ntohs (eptr->ether_type) == ETHERTYPE_LOOPBACK) {
            printf("LOOPBACK!\n");
        }
        return true;
    }

    /*
    * To handle TCP packet
    */
    bool handle_tcp(u_char *args, const u_char* packet, PCAP_PKTHEADER *pktHeader, pcap_dumper_t *pd, struct ether_header *eptr, struct iphdr *ih) {
            bool flag = true;
            // TCP packet;
            num_tcp_packet++;
            struct tcphdr *th = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

            IP_PKT pkt;

            strcpy(pkt.destAddr, inet_ntoa(*(struct in_addr*)&(ih->daddr)));
            pkt.destPort = ntohs(th->dest);
            strcpy(pkt.srcAddr, inet_ntoa(*(struct in_addr*)&(ih->saddr)));
            pkt.srcPort = ntohs(th->source);
            pkt.establish = 0;
            pkt.close = 0;

            int data_len = ntohs(ih->tot_len) - 4 * (ih->ihl) - 4 * (th->doff);

            //find connect
            if((u_int16_t)(th->syn) !=0 && (u_int16_t)(th->ack) == 0) {
                    if(cur_tcp_con == MAXTCPNUM) {
                        flag = false;
                        printf("tcp connection is refused!\n");
                        util.print_tcp_info(pkt);
                        printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                        return flag;
                    }
                    int index = util.search(pkt.srcAddr, pkt.destAddr, pkt.srcPort, pkt.destPort, buf);

                    if(index == -1) {
                        pkt.establish = 1;
                        pkt.seq1 = ntohl(th->seq) + data_len;
                        buf.push_back(pkt);
                    }

                    else {
                        if(buf[index].establish == 3) {
                                return flag;
                        }
                        buf[index].establish = 1;
                        buf[index].seq1 = ntohl(th->seq) + data_len;
                    }
            }
            else if((u_int16_t)(th->syn) != 0 && (u_int16_t)(th->ack) != 0) {
                    if(cur_tcp_con == MAXTCPNUM) {
                        flag = false;
                        return flag;
                    }
                    int index = util.search(pkt.destAddr, pkt.srcAddr, pkt.destPort, pkt.srcPort, buf);
                    if(index == -1) {
                        flag = false;
                        return flag;
                    }

                    if(buf[index].establish == 3) {
                        return flag;
                    }
                    else if(buf[index].seq1 + 1 == ntohl(th->ack_seq)) {
                        buf[index].seq2 = ntohl(th->seq) + data_len;
                        buf[index].establish = 2;
                    }
            }
            // pure ack packet
            else if((u_int16_t)(th->ack) != 0 && (u_int16_t)(th->syn) == 0 && (u_int16_t)(th->fin) == 0) {
                    int index = util.search(pkt.srcAddr, pkt.destAddr, pkt.srcPort, pkt.destPort, buf);
                    int r_index = util.search(pkt.destAddr, pkt.srcAddr, pkt.destPort, pkt.srcPort, buf);
                    if(index == -1 && r_index == -1) {
                        flag = false;
                        return flag;
                    }

                    if(index != -1) {
                        // establish
                        if(buf[index].seq2 + 1 ==  ntohl(th->ack_seq) && buf[index].establish == 2) {
                                if(cur_tcp_con == MAXTCPNUM) {
                                    flag = false;
                                    return flag;
                                }

                                buf[index].establish = 3;
                                cur_tcp_con++;
                                printf("tcp connection established!\n");
                                util.print_tcp_info(pkt);
                                printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                        }
                        // terminate
                        else {
                                switch(buf[index].close) {
                                        case 1:
                                        if(ntohl(th->ack_seq) == buf[index].seq3 + 1 && buf[index].establish == 3) {
                                                buf[index].close = 2;
                                        }
                                        break;

                                        case 2:
                                        if(ntohl(th->ack_seq) == buf[index].seq4 + 1 && buf[index].establish == 3) {
                                                buf[index].close = 3;
                                        }
                                        break;

                                        case 3:
                                        if(ntohl(th->ack_seq) == buf[index].seq4 + 1 && buf[index].establish == 3) {
                                                cur_tcp_con--;
                                                buf.erase(buf.begin()+index);
                                                printf("tcp connection terminated!\n");
                                                util.print_tcp_info(pkt);
                                                printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                                        }
                                        break;

                                        default:
                                        break;
                                } // end switch

                        }
                }
                else if(r_index != -1) {
                        switch(buf[r_index].close) {
                                case 1:
                                if(buf[r_index].seq3 + 1== ntohl(th->ack_seq) && buf[r_index].establish == 3) {
                                        buf[r_index].close = 2;
                                }
                                break;

                                case 3:
                                if((buf[r_index].seq4 + 1 == ntohl(th->ack_seq) || buf[r_index].seq3 + 1 == ntohl(th->ack_seq)) && buf[r_index].establish == 3) {
                                        cur_tcp_con--;
                                        buf.erase(buf.begin()+r_index);
                                        printf("tcp connection terminated!\n");
                                        util.print_tcp_info(pkt);
                                        printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                                }
                                break;

                                default:
                                break;
                        } // end switch
                }
            }
            //find close(FIN)
            else if((u_int16_t)(th->fin) != 0) {
                    int _i = util.search(pkt.srcAddr, pkt.destAddr, pkt.srcPort, pkt.destPort, buf);
                    int _j = util.search(pkt.destAddr, pkt.srcAddr, pkt.destPort, pkt.srcPort, buf);

                    if((_i == -1 && _j == -1) || (_i != -1 && _j != -1)) {
                            flag = false;
                            return flag;
                    }
                    else if(_i != -1 && buf[_i].establish == 3) {
                            switch(buf[_i].close) {
                                    case 0:
                                    buf[_i].close = 1;
                                    buf[_i].seq3 = ntohl(th->seq) + data_len;
                                    break;

                                    case 1:
                                    if(ntohl(th->ack_seq) == buf[_i].seq3 + 1) {
                                            buf[_i].seq4 = ntohl(th->seq) + data_len;
                                            buf[_i].close = 3;
                                    }
                                    break;

                                    case 2:
                                    buf[_i].seq4 = ntohl(th->seq) + data_len;
                                    buf[_i].close = 3;
                                    break;

                                    default:
                                    break;
                            } // end switch
                    }
                    else if(_j != -1 && buf[_j].establish == 3) {
                            switch(buf[_j].close) {
                                    case 0:
                                    buf[_j].seq3 = ntohl(th->seq) + data_len;
                                    buf[_j].close = 1;
                                    break;

                                    case 1:
                                    if(ntohl(th->ack_seq) == buf[_j].seq3 + 1) {
                                            buf[_j].seq4 = ntohl(th->seq) + data_len;
                                            buf[_j].close = 3;
                                    }
                                    else {
                                            buf[_j].seq4 = ntohl(th->seq) + data_len;
                                            buf[_j].close = 2;
                                    }

                                    case 2:
                                    buf[_j].seq4 = ntohl(th->seq) + data_len;
                                    buf[_j].close = 3;
                                    break;

                                    default:
                                    break;
                            } // end switch

                    }
            }
            // find close RST
            else if((u_int16_t)(th->rst) != 0) {
                    int _i = util.search(pkt.srcAddr, pkt.destAddr, pkt.srcPort, pkt.destPort, buf);
                    int _j = util.search(pkt.destAddr, pkt.srcAddr, pkt.destPort, pkt.srcPort, buf);

                    if(_i == -1 && _j == -1) {
                        flag = false;
                        return flag;
                    }
                    // ->
                    if(_i != -1) {
                            if(buf[_i].establish < 3) {
                                    //printf("tcp establish interrupted because of rst!\n");
                                    //print_tcp_info(pkt);
                                    return flag;
                            }
                            switch(buf[_i].close) {
                                    case 1:
                                    buf[_i].close = 2;
                                    break;

                                    case 2:
                                    cur_tcp_con--;
                                    buf.erase(buf.begin()+_i);
                                    printf("tcp connection terminated!\n");
                                    util.print_tcp_info(pkt);
                                    printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                                    break;

                                    case 3:
                                    cur_tcp_con--;
                                    buf.erase(buf.begin()+_i);
                                    printf("tcp connection terminated!\n");
                                    util.print_tcp_info(pkt);
                                    printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                                    break;

                                    default:
                                    break;
                            } // end switch
                    }
                    // <-
                    else if(_j != -1) {
                             if(buf[_j].establish < 3) {
                                    //printf("tcp establish interrupted because of rst!\n");
                                    //print_tcp_info(pkt);
                                    return flag;
                            }
                            switch(buf[_j].close) {
                                    case 1:
                                    buf[_j].close = 2;
                                    break;

                                    case 2:
                                    cur_tcp_con--;
                                    buf.erase(buf.begin()+_j);
                                    printf("tcp connection terminated!\n");
                                    util.print_tcp_info(pkt);
                                    printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                                    break;

                                    case 3:
                                    cur_tcp_con--;
                                    buf.erase(buf.begin()+_j);
                                    printf("tcp connection terminated!\n");
                                    util.print_tcp_info(pkt);
                                    printf("now # of tcp connection is: %u\n\n", cur_tcp_con);
                                    break;

                                    default:
                                    break;
                            } // end switch
                    }
            }
            return flag;
    }

    /*
    * To handle udp packet (check if it is a DNS query)
    */
    bool handle_udp(u_char *args, const u_char* packet, PCAP_PKTHEADER *pktHeader, pcap_dumper_t *pd, struct ether_header *eptr, struct iphdr *ih) {
             bool flag = true;
             struct udphdr *uh = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
             // DNS Query ?
             if(ntohs(uh->dest) == DNSPORT) {
                    printf("DNS query is found: \n");
                    printf("src addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->saddr)));
                    printf("src port: %d\n", ntohs(uh->source));
                    printf("dest addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->daddr)));
                    printf("dest port: %d\n", ntohs(uh->dest));
                    printf("udp length: %d\n\n", ntohs(uh->len));
                    flag = false;
             }

            return flag;
    }

    /*
    * To handle ARP packet (check if it an ARP request)
    */
    bool handle_arp(u_char *args, const u_char* packet, PCAP_PKTHEADER *pktHeader, pcap_dumper_t *pd, struct ether_header *eptr) {
            //fprintf(stdout,"(ARP)");
            bool flag = false;
            printf("ARP packet is found: \n");
            util.printPktHeader(pktHeader);

            string srcMac;
            string destMac;
            char tmp[100];
            string local(util.localMacAddr);

            u_char *ptr = eptr->ether_shost;
            int i = ETHER_ADDR_LEN;
            printf("src addr: ");
            do {
                    sprintf(tmp, "%s%02x",(i == ETHER_ADDR_LEN) ? "" : ":", *ptr++);  // attention:  " " -> "",  "%x" -> "02x"
                    string str(tmp);
                    srcMac += str;
            } while(--i>0);
            cout<<srcMac<<endl;

            ptr = eptr->ether_dhost;
            i = ETHER_ADDR_LEN;
            printf("des addr: ");
            do {
                    sprintf(tmp, "%s%02x",(i == ETHER_ADDR_LEN) ? "" : ":", *ptr++); // attention:  " " -> "",  "%x" -> "02x"
                    string str(tmp);
                    destMac += str;
            } while(--i>0);
            cout<<destMac<<endl<<endl;

            // local request ARP packet is allowed
            if(srcMac == local && destMac == "ff:ff:ff:ff:ff:ff") {
                    flag = true;
            }
            return flag;
        }

    /*
    * To handle IP packet
    */
    bool handle_ip(u_char *args, const u_char* packet, PCAP_PKTHEADER *pktHeader, pcap_dumper_t *pd, struct ether_header *eptr) {
            //fprintf(stdout,"(IP)");
            bool flag = true;
            struct iphdr *ih = (struct iphdr *)(packet + 14);
            if(ih->protocol == IPPROTO_UDP) {
                    flag = handle_udp(args, packet, pktHeader, pd, eptr, ih);
            } // udp
            else if(ih->protocol == IPPROTO_TCP) {
                    flag = handle_tcp(args, packet, pktHeader, pd, eptr, ih);
            } // end tcp 
            return flag;           
    }

    /*
    * To handle a packet and parse its protocle
    */
    void handle_ethernet(u_char *args, const u_char* packet, PCAP_PKTHEADER *pktHeader, pcap_dumper_t *pd) {
            total_packets++;
            struct ether_header *eptr; /* net/ethernet.h */
            bool flag = true; // is filter ?
            eptr = (struct ether_header *) packet;

            /* check to see if we have an ip packet */
            if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
                    flag = handle_ip(args, packet, pktHeader, pd, eptr);
            }// end ip
            else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
                    flag = handle_arp(args, packet, pktHeader, pd, eptr);
            }
            else {
                    flag = handle_others(args, packet, pktHeader, pd, eptr);
            }
            if(flag) {
                    count++;
                    pcap_dump((u_char *)pd, pktHeader, packet);
            } 
    }

    //global data
    int cur_tcp_con = 0;
    int num_tcp_packet = 0;
    vector<IP_PKT> buf; // to store legal tcp connections
    int MAXTCPNUM = 0;
    int count = 0; // # of total legal packets
    int total_packets = 0;
    Util util;

private:
};
#endif