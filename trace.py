# -*- coding: utf-8 -*-
#!/usr/bin/python 
from scapy.all import *
a = IP(); 
a.dst = "10.0.2.4"; 
a.ttl = 1;
b = ICMP(); 
send(a/b);

