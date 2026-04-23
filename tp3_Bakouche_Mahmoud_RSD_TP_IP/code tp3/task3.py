from scapy.all import *

DST = "192.168.56.102"   # Machine B

# Adresse source légitime même réseau que B
send(IP(src="192.168.56.50", dst=DST)/ICMP(), verbose=False)
# Adresse source d’un autre réseau
send(IP(src="10.0.2.9", dst=DST)/ICMP(), verbose=False)
#  Adresse source totalement fictive
send(IP(src="1.2.3.4", dst=DST)/ICMP(), verbose=False)

