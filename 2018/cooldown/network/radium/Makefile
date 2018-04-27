SHELL    := /bin/bash
CC       := gcc
CXXFLAGS := ${CXXFLAGS} -Wall -Wno-pointer-sign -std=gnu99

PROTOCOL_SRC  := radium.c util.c packets.c crypto.c
PROTOCOL_HDR  := radium.h util.h packets.h crypto.h
PROTOCOL_LIBS := -lcrypto -lssl

.PHONY: all clean
all: client server mitm

clean:
	rm -f server client network radium/

server: server.c ${PROTOCOL_SRC} ${PROTOCOL_HDR}
	${CC} server.c ${PROTOCOL_SRC} ${PROTOCOL_LIBS} ${CXXFLAGS} -o server

client: client.c ${PROTOCOL_SRC} ${PROTOCOL_HDR}
	${CC} client.c ${PROTOCOL_SRC} ${PROTOCOL_LIBS} ${CXXFLAGS} -o client

mitm: mitm.c ${PROTOCOL_SRC} ${PROTOCOL_HDR}
	${CC} mitm.c ${PROTOCOL_SRC} ${PROTOCOL_LIBS} ${CXXFLAGS} -o mitm

test_ping: server client
	rm -f network && mkfifo network
	./client radium.conf ping < network | ./server > network
	rm network

test_ping_open: server client
	rm -f network && mkfifo network
	./client <(head -n 1 radium.conf) ping < network | ./server > network
	rm network

test_flag: server client
	rm -f network && mkfifo network
	./client radium.conf get_flag < network | ./server > network
	rm network

test_flag_open: server client
	rm -f network && mkfifo network
	./client <(head -n 1 radium.conf) get_flag < network | ./server > network
	rm network

test_solution: server client
	./solution.py

release:
	rm -rf radium.zip radium && mkdir radium
	cp *.h client.c crypto.c packets.c radium.c server.c util.c Makefile radium/
	cp radium_example.conf radium/radium.conf
	zip radium.zip radium/*

