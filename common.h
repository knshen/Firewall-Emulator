#ifndef COMMON_H
#define COMMON_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <vector>
#include <time.h>
#include <iostream>

using namespace std;

#define DNSPORT 53 // default DNS port
typedef struct pcap_pkthdr PCAP_PKTHEADER;

/*
* data structure of a TCP connection
*/
typedef  struct  {
    char srcAddr[20];
    char destAddr[20];
    u_int16_t srcPort;
    u_int16_t destPort;

    u_int32_t seq1;  //establish
    u_int32_t seq2; //establish

    u_int32_t seq3; //close
    u_int32_t seq4; //close

    int establish;
    int close;
}  IP_PKT;

#endif