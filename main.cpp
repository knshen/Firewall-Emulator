#include "PacketHandler.hpp"

/*
* This is a demo for using firewall emulator:
* enter the project directory:
* $g++ main.cpp -o main -lpcap
* $./main dump.pcap 5 filter.pcap > procedure.txt
*/
int main(int argc, char *argv[]) {
        PacketHandler ph;
        if(argc<4)
        {
                printf("please input test filename, max tcp connections and filter file name!\n");
                return 0;
        }
        ph.MAXTCPNUM = atoi(argv[2]);

        printf ("test filename = %s\n", argv[1]);
        printf("max tcp connections: %u\n", ph.MAXTCPNUM);
        printf ("filter filename = %s\n", argv[3]);

        //read the libpcap version
        static const char *version;
        version = pcap_lib_version();
        printf("version: %s\n\n", version);
        //show device
        ph.util.showLocalDev();
        //get local mac address
        ph.util.getLocalMacAddr();
        //open the dumped cap file
        char *dev, errBuff[PCAP_ERRBUF_SIZE];
        pcap_t *handle = NULL;

        handle = pcap_open_offline( argv[1] , errBuff);

        if (NULL == handle) {
            printf("error: %s\n", errBuff);
            return (EXIT_FAILURE);
        }

        // write legal packets to filter.pcap
        pcap_dumper_t *pd = pcap_dump_open(handle, argv[3]);

        PCAP_PKTHEADER *pktHeader;
        int status;
        const u_char *pktData;
        u_char * args = NULL;

        do {
            status = pcap_next_ex(handle, &pktHeader, &pktData );
            ph.handle_ethernet(args, pktData, pktHeader, pd);
        } while (status == 1);

        // conclusion
        cout<<"# of received packets: "<<ph.total_packets<<endl;
        cout<<"# of packets droped by firewall emulator: "<<ph.total_packets - ph.count<<endl;
        cout<<"drop ratio is: "<<(ph.total_packets - ph.count) / (double)ph.total_packets<<endl;
        /*
        cout<<"size: "<<buf.size()<<endl;
        for(vector<IP_PKT>::iterator it  = buf.begin(); it != buf.end(); it++) {
                IP_PKT tmp = *(it);
                cout<<tmp.srcPort<<endl<<tmp.destAddr<<endl;
                cout<<tmp.establish<<endl;
                cout<<tmp.close<<endl<<endl;
        }
        cout<<endl;
        cout<<"******************************"<<endl;
        cout<<"# of legal packet is: "<<count<<endl;
        //close the handle
        pcap_dump_close(pd);
        pcap_close(handle);
        return (EXIT_SUCCESS);
        */
}
 
   
