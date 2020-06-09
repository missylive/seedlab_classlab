# -*- coding: utf-8 -*-
#!/usr/bin/python
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <pcap.h>

struct icmpheader {
  unsigned char icmp_type;
  unsigned char icmp_code;
  unsigned short int icmp_chksum;
  unsigned short int icmp_id;
  unsigned short int icmp_seq;
};

int main() {
   char buffer [1500];
   
   memset (buffer, 0, 1500);
  
   struct icmpheader *icmp = (struct icmpheader *)
			     (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 8;
   
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
				sizeof(struct icmpheader));

   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr(1.2.3.4);
   ip->iph_destip.s_addr = inet_addr(10.0.2.4);
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader)+
		       sizeof(struct icmpheader));


   send_raw_ip_packet (IP);
 
   return 0;

}
