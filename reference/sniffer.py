from scapy.all import*  
from scapy.layers.http import HTTPRequest # import HTTP packet
  
protocols = {1:'ICMP', 6:'TCP', 17:'UDP'}  
  
def showPacket(packet):  
    # IP
    ip_summary = packet[0][1].summary()
    string = str(packet[0][1])
    src_ip = packet[0][1].src  
    dst_ip = packet[0][1].dst  
    proto = packet[0][1].proto
    ttl = packet[0][1].ttl
    length = packet[0][1].len
    
    print(f'IP PACKET : {ip_summary}')

    try:
        test_summary = packet[0][3].summary()
        packet[0][3].display()
        print(f'TEST PACKET : {test_summary}')
        print(f'TEST PACKET : {packet[0][3]}')
    except:
        pass
  
    if proto in protocols:
  
        # TCP
        if proto == 6:
            tcp_summary = packet[0][2].summary()
            sport = packet[0][2].sport
            dport = packet[0][2].dport
            seq = packet[0][2].dport
            ack = packet[0][2].ack
            flag = packet[0][2].flags
            
            print(f"TCP PACKET : {tcp_summary}")
            print("protocol: %s: %s -> %s" %(protocols[proto], src_ip, dst_ip))
            print("src: %s -> dst: %s" %(src_ip, dst_ip))
            print("TTL: %s Length: %s" %(ttl, length))
            print("sport: %s dport: %s" %(sport, dport))
            print("seq: %s ack: %s flag: %s" %(seq, ack, flag))
            print("\n")

        # UDP
        if proto == 17:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            udp_length = packet[UDP].len
            print("protocol: %s" %(protocols[proto].upper()))
            print("src: %s -> dst: %s TTL: %s" %(src_ip, dst_ip, ttl))
            print("sport: %s dport: %s Packet Length: %s" %(sport, dport, udp_length))
            print("\n")
  
def sniffing(filter):  
    sniff(filter = filter, prn = showPacket, count = 0)  
  
if __name__ == '__main__':  
    filter = 'port 80'  
    sniffing(filter)