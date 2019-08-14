all: arp_spoof

arp_spoof: main.o arpspoof.o get_mymac.o get_senmac.o packet_relay.o
	gcc -o arp_spoof main.o arpspoof.o get_mymac.o get_senmac.o packet_relay.o -lpcap

arpspoof.o: header.h arpspoof.cpp
	gcc -c -o arpspoof.o arpspoof.cpp

get_mymac.o: header.h get_mymac.cpp
	gcc -c -o get_mymac.o get_mymac.cpp

get_senmac.o: header.h get_senmac.cpp
	gcc -c -o get_senmac.o get_senmac.cpp

packet_relay.o: header.h packet_relay.o
	gcc -c -o packet_relay.o packet_relay.cpp

main.o: header.h main.cpp
	gcc -c -o main.o main.cpp

clean:
	rm -rf main.o arpspoof.o get_mymac.o get_senmac.o packet_relay.o arp_spoof
