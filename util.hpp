#ifndef UTIL_H
#define UTIL_H
#include "common.h"


class Util {
public:
	/*
	* To find the target packet in the buffer according to source/dest port and source/dest ip address
	*/
	int search(char srcA[], char destA[], u_int16_t srcP, u_int16_t destP, vector<IP_PKT> buf) {
    		for(int i=0; i<buf.size(); i++) {
        			IP_PKT tmp = buf[i];
        			if(strcmp(srcA, tmp.srcAddr) == 0 && strcmp(destA, tmp.destAddr) == 0 && srcP == tmp.srcPort && destP == tmp.destPort) {
            				return i;
        			}
    		}
    		return -1;
   	}

   	int printPktHeader(PCAP_PKTHEADER *pktHeader) {
    		printf("cap_time:%u, ", (unsigned int)pktHeader->ts.tv_sec);
    		printf("pkt length:%u, ", pktHeader->len);
    		printf("cap length:%u\n", pktHeader->caplen);
	}

	void showLocalDev() {
    		char *dev, errbuf[1024];
    		dev=pcap_lookupdev(errbuf);
    		if(dev==NULL){
       			printf("couldn't find default device: %s\n",errbuf);
        			return;
    		}
     		printf("fidn success: device :%s\n",dev);

     		char errbuf1[1024];
     		struct in_addr addr;
     		char *net,*mask;
    		bpf_u_int32 netp,maskp;
    		int err=pcap_lookupnet(dev,&netp,&maskp,errbuf1);
    		if(err==-1) {
         			printf("couldn't detect the ip and maskp: %s\n",errbuf1);
         			return;
     		}

     		addr.s_addr=netp;
     		net=inet_ntoa(addr);
     		if(net==NULL){
         			printf("ip error\n");
         			return;
      		}
      		printf("ip: %s\n",net);

      		addr.s_addr=maskp;
      		mask=inet_ntoa(addr);
      		if(mask==NULL){
            			printf("mask errorn");
            			return;
       		}
       		printf("mask: %s\n",mask);
	}

	/*
	*print address and port info of a packet
	*/
	void print_tcp_info(IP_PKT pkt) {
         		printf("src: %s.%u\n", pkt.srcAddr, pkt.srcPort);
         		printf("dest %s.%u\n", pkt.destAddr, pkt.destPort);
	}	

	/*
	*print detail info of a packet
	*/
	void print_pkt_detail(struct tcphdr *th) {
        		printf("flag ACK: %u\n", (u_int16_t)(th->ack));
        		printf("flag FIN: %u\n", (u_int16_t)(th->fin));
        		printf("flag SYN: %u\n", (u_int16_t)(th->syn));
       		printf("seq: %u\n", ntohl(th->seq));
       		printf("ack_seq: %u\n", ntohl(th->ack_seq));
        		printf("window: %u\n\n", ntohs(th->window));
	}

	/*
	* get local mac address
	*/
	void getLocalMacAddr() {
    		struct ifreq tmp;
   		int sock_mac;
    		char mac_addr[30];
    		sock_mac = socket(AF_INET, SOCK_STREAM, 0);
    		if( sock_mac == -1) {
        			perror("create socket fail\n");
        			return;
    		}
   		memset(&tmp, 0, sizeof(tmp));
    		strncpy(tmp.ifr_name, "eth0", sizeof(tmp.ifr_name)-1 );
    		if( (ioctl( sock_mac, SIOCGIFHWADDR, &tmp)) < 0 ) {
        			printf("mac ioctl error\n");
        			return;
    		}
    		sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            		(unsigned char)tmp.ifr_hwaddr.sa_data[0],
            		(unsigned char)tmp.ifr_hwaddr.sa_data[1],
            		(unsigned char)tmp.ifr_hwaddr.sa_data[2],
            		(unsigned char)tmp.ifr_hwaddr.sa_data[3],
           		(unsigned char)tmp.ifr_hwaddr.sa_data[4],
            		(unsigned char)tmp.ifr_hwaddr.sa_data[5]
            		);
    		close(sock_mac);
   		memcpy(localMacAddr, mac_addr, strlen(mac_addr));
	}

	char localMacAddr[30];

private:
};

#endif















