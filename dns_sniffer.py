from scapy.all import*
from dnslib import DNSRecord
  
protocols = {1:'ICMP', 6:'TCP', 17:'UDP'}  

count = 1
sniffing_time = input("Sniffing Time: ")

def showPacket(packet):    
    global count
    # IP HEADER
    src_ip = packet[0][1].src  
    dst_ip = packet[0][1].dst  
    proto = packet[0][1].proto
    ttl = packet[0][1].ttl
    length = packet[0][1].len

    if proto in protocols:

        # UDP
        if proto == 17:
            sport = packet[0][2].sport
            dport = packet[0][2].dport
            udp_length = packet[0][2].len
            
            try : 
                # DNS HEADER
                dns_id = packet[0][3].id
                qr = packet[0][3].qr
                opcode = packet[0][3].opcode

                # DNS Question Record
                qname = packet[0][3].qd.qname
                qtype = packet[0][3].qd.qtype
                qclass = packet[0][3].qd.qclass

                # DNS SOA Resource Record
                rrname = packet[0][3].ns.rrname
                type = packet[0][3].ns.type
                rclass = packet[0][3].ns.rclass
                ttl = packet[0][3].ns.ttl
                rdlen = packet[0][3].ns.rdlen
                mname = packet[0][3].ns.mname
                rname = packet[0][3].ns.rname
                serial = packet[0][3].ns.serial
                refresh = packet[0][3].ns.refresh
                retry = packet[0][3].ns.retry
                expire = packet[0][3].ns.expire
                minimum = packet[0][3].ns.minimum

                print('==<IP HEADER>==')
                print("protocol: %s: %s -> %s" %(protocols[proto], src_ip, dst_ip))
                print("src: %s -> dst: %s" %(src_ip, dst_ip))
                print("TTL: %s Length: %s" %(ttl, length))
                print('==<UDP HEADER>==')
                print("protocol: %s" %(protocols[proto].upper()))
                print("sport: %s dport: %s Packet Length: %s" %(sport, dport, udp_length))    
                print('==<DNS HEADER>==')
                print(f'id : {dns_id}')
                print(f'qr : {qr}')
                print(f'opcode : {opcode}')
                print('###[ DNS Question Record ]###')
                print(f'qname : {qname}')
                print(f'qtype : {qtype}')
                print(f'qclass : {qclass}')
                print('###[ DNS SOA Resource Record ]###')
                print(f'rrname : {rrname}')
                print(f'type : {type}')
                print(f'rclass : {rclass}')
                print(f'ttl : {ttl}')
                print(f'rdlen : {rdlen}')
                print(f'mname : {mname}')
                print(f'rname : {rname}')
                print(f'serial : {serial}')
                print(f'refresh : {refresh}')
                print(f'retry : {retry}')
                print(f'expire : {expire}')
                print(f'minimum : {minimum}')
                print("\n")
            except:
                pass
    count += 1
  
def sniffing(filter):  
    print("Sniffing Start")
    pcap_file = sniff(prn = showPacket,timeout=int(sniffing_time), filter = filter, count=0)
    print("Finish Capture Packet")
    if count == 1:
            print("No Packet")
            sys.exit()
    else:
        print("Total Packet: %s" %(count-1))
        file_name = input("Enter File Name: ")
        wrpcap(str(file_name), pcap_file)  
  
if __name__ == '__main__':  
    filter = 'port 53'  
    sniffing(filter)