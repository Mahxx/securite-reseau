src_ip = "1.2.3.4"
dst_ip = "10.222.193.51"  
packet_id = 1234

size = 1000  
num=70 
for i in range(num):
    ip = IP(src=src_ip, dst=dst_ip)
    ip.id = packet_id  
   
    if i == 0:
        #premier fragment
        ip.frag = 0
        ip.flags = 1
        
        udp = UDP(sport=7070, dport=9090)
        udp.len = num * size + 8  
        
        payload = chr(65 + (i % 26)) * size  
        pkt = ip/udp/payload
        pkt[UDP].checksum = 0
        
    elif i == num - 1:
        # dernier fragment
        offset = (8 + i * size) // 8
        ip.frag = offset
        ip.flags = 0 
        
        payload = chr(65 + (i % 26)) * size
        pkt = ip/payload

    else:
        # autre fragment
        offset = (8 + i * size) // 8
        ip.frag = offset
        ip.flags = 1 
        
        payload = chr(65 + (i % 26)) * size
        pkt = ip/payload
    
    send(pkt, verbose=0)
    