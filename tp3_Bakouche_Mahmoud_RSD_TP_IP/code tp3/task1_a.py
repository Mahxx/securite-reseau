#!/usr/bin/python3
from scapy.all import *

DST = "10.222.193.51"   # IP de la machine B
SRC = "1.2.3.4"
ID  = 1234

ip1 = IP(src=SRC, dst=DST, id=ID, flags="MF", frag=0)
udp = UDP(sport=7070, dport=9090)
payload1 = b'A' * 32

pkt1 = ip1/udp/payload1
pkt1[UDP].checksum = 0
send(pkt1, verbose=False)

ip2 = IP(src=SRC, dst=DST, id=ID, flags="MF", frag=5)
payload2 = b'B' * 32
send(ip2/payload2, verbose=False)

ip3 = IP(src=SRC, dst=DST, id=ID, flags=0, frag=9)
payload3 = b'C' * 32
send(ip3/payload3, verbose=False)