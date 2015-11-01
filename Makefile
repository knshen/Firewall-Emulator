CC = gcc
GG = g++

LIBS = -lpcap

all: firewall

util.o: util.hpp
	$(GG) -c $^ $(LIBS)
firewall: main.cpp
	$(GG) -o $@ $^  $(LIBS)

PacketHandler.o: PacketHandler.hpp
	$(GG) -c $^ $(LIBS)
	
clean:
	rm -rf *.o firewall
	rm -rf *.txt
	rm -rf *.res
	rm -rf *.gch
	

