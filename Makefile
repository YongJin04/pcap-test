# Makefile for pcap-test.c

CC=gcc
CFLAGS=-Wall
LIBS=-lpcap

TARGET=pcap-test
SRC=pcap-test.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
