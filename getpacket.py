# -*- coding: utf-8 -*-
#!/usr/bin/python2.7.12 
#include <stdio.h>
#include <string.h>
#include <socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <rfpimp>
import socket
#include <void.h>
#include <int.h>
#include <struct.h>
import struct
import void

void main ():
{
	struct sockaddr_in server;
	struct sockaddr_in client;
	int clientlen;
	char buf[1500];

	int sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset ((char *) &server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = hton1(INADDR_ANY);
	server.sin_port = htons(9090);

	if (bind(sock, (struct sockaddr *) &server, sizeof(server)) <0):
	   error("ERROR on binding");

	while (1): {
	    bzero(buf, 1500);
	    recvfrom(sock, buf, 1500-1, 0,
			(struct sockaddr *) &client, &clientlen);
	    printf("%s\n", buf);
	}
	close(sock);
}


