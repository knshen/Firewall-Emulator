# Overview
An emulated firewall (int user mode) in C++

# Functions
* Dump packets to a pcap file using tcpdump
* Identify outgoing DNS queries and coming ARP requests
* Identify and monitor TCP connections' establishments and terminations, when the number of TCP connections exceed the upper limit, drop such packets.
* All the intermediate result will be recorded at procedure.res

Remember it just emulates the behavior of real world firewall, but cannot do something real to the packets.  

# File Directory
**autoVisit.sh:** a script to automatically wget websites, you can configure your own websites' URLs
**dump.pcap:** an demo pcap file produced by tcpdump
**Makefile:** makefile of this project
**easy_run.sh:** demo script
**common.h main.cpp PacketHandler.hpp util.hpp:** source code files 

# Presuppositions
* flex [http://sourceforge.net/projects/flex/files/]
* bison [ftp://ftp.gnu.org/gnu/bison/]
* GNU M4 [ftp://ftp.gnu.org/gnu/m4/]
* libpcap [http://www.tcpdump.org/]
* tcpdump [http://www.tcpdump.org/]
If you use source code install, use **./configure, sudo make, sudo make install** to install.

# Quick Start
use **sh easy_run.sh** ro run the example with the dump file dump.pcap

# Usage
## How to produce dump file
There are two ways to get a dump file
* do manually:
**tcpdump -w example.pcap**, and browse some web pages.
* use autoVisit.sh:
**tcpdump -w example.pcap**, and run **sh autoVisit.sh** in another terminal. You can configure your own URLs in autoVisit.sh

## How to run firewall emulator
**make clean**
**make**
**./firewall p1 p2 p3**, where p1 is the dump file name, like "dump.pcap"; p2 is the max number of allowed TCP connections; p3 is the filtered dump file name, like "filter.pcap".
For example, ./firewall dump.pcap 10 filter.pcap



