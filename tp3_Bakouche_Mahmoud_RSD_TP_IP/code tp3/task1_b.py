from scapy.all import *
import time 

DST = "10.222.193.51"
SRC = "1.2.3.4"
ID  = 12345
# Fragment 2 : B (16 → 39) → chevauchement 8 octets
f2 = IP(src=SRC, dst=DST, id=ID, flags=0, frag=2) / Raw(b"B"*24)
# Fragment 1 : A (0 → 23)
time.sleep(5)
f1 = IP(src=SRC, dst=DST, id=ID, flags="MF", frag=0) / Raw(b"A"*24)



send(f1, verbose=False)
send(f2, verbose=False)