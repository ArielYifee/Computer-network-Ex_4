# Makefile for Sniffer and send ping project
CC = gcc
W = -Wall
L = -lpcap

all: myping sniffer

myping: myping.c
	$(CC) $(W) -o myping myping.c

sniffer: sniffer.c
	$(CC) sniffer.c $(L) $(W) -o sniffer
	
.PHONY: clean all
clean:
	rm -f  *.o *.a *.so sniffer myping

runPing:
	sudo ./myping

runSniff:
	sudo ./sniffer
