#!/usr/bin/env python3 
from scapy.all import *


def create():
    dns = DNS(id=0xAAAA, qr=0, qdcount=1,
              ancount=0, nscount=0, arcount=0,
              qd=DNSQR(qname='www.example.com'))
    ip, udp = IP(dst='10.9.0.53', src='10.9.0.11'),\
              UDP(dport=53, sport=33333 ,chksum=0)
    return ip/udp/dns



if __name__ == '__main__':
    send(create(), verbose=0)
