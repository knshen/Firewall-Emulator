# run example use all default parameters
make clean
make
sudo ./firewall dump.pcap 10 filter.pcap > procedure.res
